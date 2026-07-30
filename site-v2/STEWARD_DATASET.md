# Steward Cloud Dataset Boundary

This document supersedes the former Steward task archive contract. It defines
the Site V2 consumer view of the public cloud publication; it is not a second
producer schema. Producer validation, publication ordering, D1 tables, R2 key
grammar, and disclosure rules live in the [Steward cloud
contracts](../contracts/steward-cloud/README.md).

The former placement-public raw filesystem tree, rsync transport, importer,
and local cache are historical context only. They are not Site V2 inputs and
must not be treated as a compatible ingestion model. The durable reader
contracts are [DATA.md](DATA.md), [API.md](API.md), [FUNCTIONAL.md](FUNCTIONAL.md),
and [QUALITY.md](QUALITY.md).

## Public source and visibility

Site V2 is a standalone Next.js Node reader. It uses server-side native
`fetch` for Cloudflare D1 and anonymous public R2. It never writes D1, runs a
Worker or sidecar, scans a local archive, or accepts a caller-supplied object
URL. The four server-only values are the Cloudflare account ID, D1 database ID,
account-scoped D1 Read token, and anonymous public R2 base URL.

The public source is one visible D1 task head joined to its visible publication
generation. A query is valid only when all rows belong to that generation and
pass the public disclosure contract. Staged, superseded, hidden, malformed,
dangling, or private-shaped rows are invisible and fail closed. A new visible
generation atomically supersedes the previous head; there is no history
migration or compatibility read path.

A generation contains one task and its complete bounded publication graph. A
completed planning run may be published while the task lifecycle is still
`active`; later completed runs may replace the immutable head. Publication
identity and object identity come from canonical metadata/content digests, not
attempt counters or wall-clock values.

## Task graph

The visible graph has these relationships:

- `task` is the stable task identity, title, lifecycle state, timestamps, and
  disclosure state.
- `pipelines` belong to the task and retain their stable pipeline identity and
  ordering.
- Terminal, immutable `runs` belong to both a task and a pipeline. A run may
  expose a complete sanitized ATIF artifact.
- Ordered task-local `events` belong to the task. The reader checks ownership,
  expected count, and a contiguous sequence beginning at one.
- `artifacts` belong to a task and run. Each descriptor carries a logical path,
  media type, byte size, lower-case SHA-256, availability, and disclosure
  booleans.

Each completed run's ATIF artifact ID and digest must resolve to an artifact
owned by that same task and run. A dangling or mismatched link makes the graph
invalid rather than exposing an incomplete trajectory.

Task summaries are complete within their bounded page and include the owning
pipeline, completed-run identity when present, event and artifact counts, and
`completeness: "complete"`. Task detail is all-or-nothing: Site validates
ownership, counts, event order, run timing, artifact identity, and disclosure
before returning any graph field.

## Immutable public objects

Public R2 objects are sanitized, immutable, and content addressed. A public
artifact key is derived only after validating the descriptor and has this exact
shape:

```text
v1/tasks/{taskId}/objects/sha256/{sha256[0:2]}/{sha256}
```

The digest prefix and task ID in the key must match the descriptor. Logical
paths remain metadata in D1; they are not URLs or filesystem paths. Site's
same-origin artifact action resolves one descriptor and returns one `307`
redirect to the configured anonymous base. It never proxies bytes or exposes a
bucket, private locator, credential, scanner result, or filesystem path.

An optional private original may exist for producer recovery, but it is never
written to D1 or ATIF and is never read by Site V2. Public output contains only
the bounded disclosure facts `redactionApplied` and `originalRetained`.

## Complete trajectory

The transcript route is a descriptor for one selected completed run, not a raw
transcript stream. Its artifact is a complete, terminal, sanitized ATIF-v1.7
document. The descriptor includes task, pipeline, and run identity; role and
state; start and completion timestamps; exact duration; optional artifact ID;
`mediaType: "application/json"`; byte size; SHA-256; public key; availability;
and disclosure.

The response never returns raw ATIF, a partial record set, a JSONL prefix, a
cursor, a direct R2 URL, or a lossy fallback. The reader verifies the artifact
descriptor against the run and D1 artifact before exposing it. A task may have
an active lifecycle and still expose its completed planning trajectory.

## Responses and failure states

Steward cloud status, task-page, task-detail, trajectory-descriptor, and
problem responses use `schemaVersion: "3.0"`. Unrelated Site APIs retain their
own versions. A valid empty publication is distinct from unavailable data.

The reader distinguishes transient D1/R2/network/timeout/server failures from
terminal missing, resource, integrity, schema, ownership, and configuration
failures. Only the documented transient classes offer a manual retry. Site
never polls, retries automatically, returns a partial graph, or synthesizes
zero evidence from absent rows.

## Validation ownership

The producer builds and validates a complete publication before exposing its
generation. Site independently validates D1 response bounds, schema, row
ownership, counts, event sequence, run duration, content-addressed keys,
artifact hashes, and disclosure before normalization or rendering. The
executable producer contract remains in
[`contracts/steward-cloud/`](../contracts/steward-cloud/); the reader behavior
and response shapes remain in [DATA.md](DATA.md) and [API.md](API.md).

## Explicit non-goals

This contract does not define or permit:

- a raw task tree, placement-public disclosure, rsync, filesystem watching,
  importer reconciliation, or a local SQLite cache;
- raw prompts, commands, partial JSONL, local transcript/artifact reads, or
  authenticated R2 access;
- private-original access, a raw fallback, a compatibility reader, or
  historical archive migration; or
- a global signal, planner, revision, snapshot, or inferred control-loop
  publication. Those availability boundaries are recorded in
  [STEWARD_CONTROL_LOOP.md](STEWARD_CONTROL_LOOP.md).

### Historical context (non-normative)

Steward previously mirrored task directories and control-loop files for local
research and recovery. That design exposed placement and transport details to
the reader. It is retained only to explain why this document supersedes the
older archive language; it supplies no current schema, route, or fallback.
