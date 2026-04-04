# Generic RFC And Internet-Draft Support In Local RAG Design

## Status

Approved in conversation on 2026-04-04.

## Context

`coquic` keeps a local QUIC and HTTP/3 text corpus under `docs/rfc/` and builds a
repo-local RAG index from every `*.txt` file in that directory.

The current corpus and tooling are RFC-centric:

- the bundle contains only RFC text files plus documentation metadata
- the ingest parser expects `Request for Comments: NNNN` in the source text
- the parsed document model uses an integer RFC number as the primary identity
- graph nodes, vector payloads, and query outputs all assume `rfc: int`
- CLI commands such as `get-section` and `related-sections` select documents by
  RFC number only

That is sufficient for stable published QUIC RFCs, but it breaks down for
current QUIC working-group drafts.

The immediate motivating case is qlog. The latest qlog working-group drafts were
downloaded into `docs/rfc/` on 2026-04-04:

- `draft-ietf-quic-qlog-main-schema-13.txt`
- `draft-ietf-quic-qlog-quic-events-12.txt`
- `draft-ietf-quic-qlog-h3-events-12.txt`

Those drafts are useful source material for upcoming qlog work, but they cannot
be indexed correctly by the current parser because they are Internet-Drafts, not
RFCs.

The user wants draft support to be generic, not qlog-specific, and wants:

- true document identifiers such as `draft-ietf-quic-qlog-main-schema-13`
- drafts to appear in normal search results by default
- CLI document selection to use a general document identifier instead of an RFC
  number

## Goal

Extend the local RAG source pipeline and query surface so that `docs/rfc/`
supports both RFCs and Internet-Drafts as first-class documents.

After this change:

- RFCs continue to work under identifiers like `rfc9000`
- Internet-Drafts work under identifiers like
  `draft-ietf-quic-qlog-main-schema-13`
- normal search spans both RFCs and drafts by default
- document-specific commands select sources by a general document identifier
- the qlog drafts already fetched into `docs/rfc/` can be indexed and queried
  without special-case handling

## Non-Goals

- changing the local corpus layout away from `docs/rfc/*.txt`
- implementing qlog logging in the transport stack
- adding non-IETF source formats such as HTML, XML, Markdown, or PDFs
- preserving the RFC-only CLI interface
- building separate indexes for RFCs and drafts

## Decisions

### 1. Promote `doc_id` To The Primary Document Identity

The ingest and query stack should stop using `rfc: int` as the primary document
key.

Each parsed source document gets:

- `doc_id: str` as the canonical selector
- `doc_kind: "rfc" | "internet-draft"`
- `title: str`
- optional RFC-specific metadata such as `rfc_number`
- optional draft-specific metadata such as `draft_name`

Examples:

- RFC 9000: `doc_id = "rfc9000"`
- qlog main schema draft:
  `doc_id = "draft-ietf-quic-qlog-main-schema-13"`

This is the smallest generic model that fits both current RFC texts and future
IETF drafts without another identity migration.

### 2. Parse Both RFC And Internet-Draft Front Matter

The parser should detect document kind from the source text itself.

RFC parsing continues to rely on `Request for Comments: NNNN`.

Internet-Draft parsing should extract the draft name from the front matter line
that contains the canonical draft identifier, for example:

- `draft-ietf-quic-qlog-main-schema-13`

Section extraction remains shared. Both RFCs and drafts should produce:

- a document record
- per-section records
- section citations
- graph nodes and edges

The section parser must not depend on the document being an RFC once the top
level identity has been established.

### 3. Search Across All Indexed Documents By Default

Normal semantic search should include both RFCs and drafts unless the caller
provides a document filter.

This matches the user requirement that drafts appear in ordinary search results
without explicit opt-in.

Document-specific commands should accept a selector such as:

- `--doc rfc9000`
- `--doc draft-ietf-quic-qlog-main-schema-13`

The old `--rfc` selector is intentionally removed rather than preserved as a
parallel interface.

### 4. Preserve RFC Metadata As Optional Compatibility Data

RFCs still matter as a stable published source and should retain structured RFC
metadata.

The document model and query results should therefore keep optional RFC-specific
fields for RFC documents, but these fields no longer drive indexing or lookup.

That yields:

- generic logic keyed by `doc_id`
- RFC-aware output when helpful
- no special synthetic numbering scheme for drafts

### 5. Move Graph And Vector Payloads To Document-Centric Keys

Graph nodes and vector payloads currently assume an integer RFC number and node
IDs of the form `rfc9000#18.2`.

These should become document-centric:

- section node IDs become `<doc_id>#<section_id>`
- vector payloads store `doc_id` and `doc_kind`
- RFC-specific payload fields remain optional

This change keeps joins and citations stable across mixed document kinds and
avoids inventing fake RFC numbers for drafts.

### 6. Keep `docs/rfc/` As The Unified Source Bundle

The `docs/rfc/` directory remains the single source set for QUIC-related RFCs
and drafts used by the repo-local RAG.

`docs/rfc/README.md` and `docs/rfc/manifest.json` should be updated to describe
the expanded corpus clearly:

- RFCs remain listed as published standards
- drafts are listed separately as tracked working-group drafts
- qlog drafts become part of the documented bundle

The manifest remains documentation-oriented metadata. The build pipeline still
discovers source texts from `docs/rfc/*.txt`.

## Architecture

### Ingest Model

Generalize the current RFC-only ingest model:

- `RfcDocument` becomes a generic document type
- `RfcSection.rfc` becomes a document identifier field
- citations remain section-local and document-relative

Recommended fields:

- document:
  - `doc_id`
  - `doc_kind`
  - `title`
  - `rfc_number | None`
  - `draft_name | None`
  - `sections`
- section:
  - `doc_id`
  - `section_id`
  - `title`
  - `text`
  - `citations`

The rest of the ingest pipeline should consume that generic shape instead of
branching on RFC versus draft logic.

### Parser

Refactor the parser into:

1. source classification and top-level metadata extraction
2. shared section extraction
3. shared citation extraction

This keeps the format-specific logic limited to the document header while
leaving the section and citation machinery common.

### Graph Extraction

Graph artifacts should use document-scoped identities:

- document node IDs:
  - `doc:rfc9000`
  - `doc:draft-ietf-quic-qlog-main-schema-13`
- section node IDs:
  - `rfc9000#18.2`
  - `draft-ietf-quic-qlog-main-schema-13#2`

Term extraction remains generic. Existing QUIC frame and transport-parameter
heuristics can continue to operate on section titles and bodies without caring
whether the source is an RFC or a draft.

### Query Surface

Query service and CLI updates should include:

- replace RFC-number filters with `doc_id` filters
- include `doc_id` and `doc_kind` in result payloads
- keep RFC number in output when the source is an RFC
- update examples, tests, and diagnostics to use `--doc`

Search commands continue to work without a document filter and now return mixed
RFC and draft results.

## Data Flow

1. `docs/rfc/*.txt` is enumerated as before.
2. Each source file is parsed into a generic document model.
3. Section records and graph artifacts are emitted with `doc_id`.
4. Vector payloads store `doc_id` and `doc_kind`.
5. Query commands optionally filter by `doc_id`.
6. Search results and section fetches surface draft names directly.

## Error Handling

- A source text that is neither a recognizable RFC nor a recognizable
  Internet-Draft should fail parsing with a clear error.
- Duplicate `doc_id` values in the source set should fail the build.
- Query commands should report unknown document identifiers explicitly.
- Existing section lookup failures should continue to return a structured
  not-found result, but keyed by `doc_id` instead of RFC number.

## Testing

Add or update tests for:

- parsing a known RFC into `doc_id = "rfc9000"`
- parsing a draft fixture into its true draft identifier
- section and citation extraction on draft input
- graph node IDs and vector payloads using `doc_id`
- CLI lookup by `--doc` for both RFCs and drafts
- mixed-corpus search returning draft results by default
- doctor/build-index operating successfully on a source directory containing
  both RFCs and drafts

Verification after implementation should include:

- rebuilding `.rag` from the live `docs/rfc/` corpus
- running `doctor` successfully
- querying one qlog draft section directly by draft name
- confirming that ordinary search can return qlog draft sections

## Open Tradeoffs

### Document Result Presentation

The query output will become slightly more verbose because results need to carry
`doc_id` and `doc_kind` instead of only an RFC number. This is acceptable
because correctness and genericity matter more than preserving the older
RFC-only shape.

### Citation Scope

The current citation extractor treats references like `Section 4.1` as
document-local. That remains acceptable for this slice. Cross-document citation
resolution can be a separate follow-up if needed.
