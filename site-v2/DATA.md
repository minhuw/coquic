# Canonical Data Contract

Site V2 is a standalone Next.js Node reader for Steward's public cloud
publication. Cloudflare D1 contains validated public metadata and Cloudflare R2
contains immutable sanitized objects. Acquisition, validation/normalization,
domain state, and rendering remain separate. The former filesystem archive,
rsync convergence, in-process importer, local cache, and raw control-loop peer
are historical producer/reader designs, not inputs to this contract.

The D1 reader uses native server-side `fetch` against the Cloudflare REST API.
It reads only visible publication relationships and never mutates D1. R2 URLs
are anonymous and are derived from validated content-addressed artifact identity;
Site does not accept or proxy a caller-supplied object URL.

## Envelope

Unrelated first-party resources retain their existing major versions. Steward
cloud status, task page, task detail, trajectory descriptor, and problem
responses use `schemaVersion: "3.0"`:

```json
{
  "schemaVersion": "3.0",
  "generatedAt": "2026-07-19T12:00:00Z",
  "data": {}
}
```

Collection responses MAY add pagination data; generated evidence SHOULD add
`provenance`. Cloud problems use the `problem` member in
`schemas/steward-cloud.schema.json` and do not use the success `data` member.

## Naming and scalar rules

- JSON property names use `camelCase`; URLs and query parameters use lower-case
  kebab or the documented short names.
- Timestamps are UTC RFC 3339 strings with a `Z` suffix.
- Calendar dates are `YYYY-MM-DD`.
- IDs are opaque non-empty strings and are never inferred from display labels.
- Git commits are 40 lower-case hexadecimal characters when full identity exists.
- Byte counts are non-negative integers. Durations are milliseconds; latency is
  microseconds; throughput is bits/second; memory is bytes; utilization is 0-1.
- Unknown optional numeric values are `null` or omitted, never zero.
- Percentages are derived from covered/total or ratio values and SHOULD NOT be
  serialized alongside their source values.
- Arrays preserve producer order unless the resource explicitly defines sorting.

## Referential integrity

- IDs are unique within their resource and remain stable across snapshots when
  they identify the same logical entity.
- Every performance measurement references an implementation in the same
  snapshot. Measurement IDs are unique within a snapshot.
- Every interop lane references two published participants. Every result and
  every `testcaseOrder` entry references a published testcase. A lane contains at
  most one result per testcase.
- Every Steward integration/task/signal reference resolves within the current
  publication or is explicitly identified as a retained external reference.
- Pagination totals describe the filtered collection, not the unfiltered source.
- `covered` MUST be less than or equal to `total`; token subtotals MUST sum to
  `total`; utilization samples of zero require utilization values to be `null`.

## Provenance

Evidence resources use:

```json
{
  "producer": "github-actions/perf",
  "event": "schedule",
  "commit": "40-character-sha",
  "runId": "29676688665",
  "sourceUrl": "https://github.com/.../actions/runs/29676688665",
  "completeness": "complete"
}
```

`completeness` is `complete`, `partial`, or `unknown`. Partial resources MUST
include `warnings` identifying omissions.

## Resource catalog

| Resource               | Canonical V2 path                             | Schema definition                                 |
| ---------------------- | --------------------------------------------- | ------------------------------------------------- |
| Random QA question     | `/api/v2/qa/suggestion`                       | `qa.schema.json#/$defs/suggestionResponse`        |
| QA stream              | `/api/v2/qa/stream`                           | `qa.schema.json#/$defs/streamEvent`               |
| Transcript search      | `/api/v2/transcripts`                         | `transcript.schema.json#/$defs/searchResponse`    |
| Transcript detail      | `/api/v2/transcripts/{id}`                    | `transcript.schema.json#/$defs/detailResponse`    |
| Transcript JSONL       | `/api/v2/transcripts/{id}/raw`                | JSONL records                                     |
| Dataset archive        | `/dataset/{safeFilename}`                     | ZIP binary                                        |
| Performance current    | `/api/v2/evidence/performance/current`        | `evidence.schema.json#/$defs/performanceSnapshot` |
| Performance history    | `/api/v2/evidence/performance/history`        | `evidence.schema.json#/$defs/historyIndex`        |
| Performance snapshot   | `/api/v2/evidence/performance/snapshots/{id}` | performance snapshot                              |
| Interop snapshot       | `/api/v2/evidence/interop/current`            | `evidence.schema.json#/$defs/interopSnapshot`     |
| Coverage snapshot      | `/api/v2/evidence/coverage/current`           | `evidence.schema.json#/$defs/coverageSnapshot`    |
| Steward cloud status    | `/api/steward/status`                         | `steward-cloud.schema.json#/$defs/statusResponse` |
| Steward cloud task page | `/api/steward/tasks`                          | `steward-cloud.schema.json#/$defs/taskPageResponse` |
| Steward cloud task      | `/api/steward/tasks/{taskId}`                 | `steward-cloud.schema.json#/$defs/taskDetailResponse` |
| Steward trajectory descriptor | `/api/steward/tasks/{taskId}/transcript?run={runId}` | `steward-cloud.schema.json#/$defs/trajectoryDescriptorResponse` |
| Steward logical artifact | `/api/steward/tasks/{taskId}/artifact?path={logicalPath}` | one validated `307` redirect |
| Retired revision domain | `/api/steward/revision`                       | `steward-cloud.schema.json#/$defs/problemResponse` (`410`) |

The browser-local Workbench command/event protocol is defined by
`workbench.schema.json` and [WORKBENCH.md](WORKBENCH.md); it is not an HTTP API.

Stable unrelated evidence, QA, transcript, and dataset paths retain their
documented contracts. Steward's raw archive and control-loop compatibility paths
are not reader inputs; retired global domains return the cloud `410` problem
instead of a compatibility read.

## Steward cloud publication

The public source is the visible D1 publication graph, not a filesystem tree.
Every cloud query joins a `visible` `task_heads` row to its referenced `visible`
`publication_generations` row and the same-publication task data. Staged,
superseded, hidden, malformed, dangling, or private-shaped rows fail closed.
The account-scoped D1 Read token is server-only because Cloudflare cannot scope it
to one database; all rows reachable through it must therefore be public-safe.

The four server values are Cloudflare account ID, D1 database ID, D1 Read token,
and anonymous public R2 base URL. The reader has no Worker, D1 write, local
SQLite/cache, sidecar, compatibility reader, raw fallback, or history migration.
Builds and tests do not require live cloud credentials.

### Public identity and relationships

Cloud task pages expose complete summaries ordered within either `active` or
terminal `history` scope. A summary carries `taskId`, title, lifecycle state,
creation/completion timestamps, `completeness: "complete"`, the owning
`pipelineId`, the completed `runId` when present, event/artifact counts, and
disclosure flags. Cursors are opaque, scope-bound to the latest visible
publication, and stale cursors are terminal errors.

Task detail is an all-or-nothing graph containing `task`, `pipelines`, `runs`,
ordered `events`, `artifacts`, and an optional `trajectory` descriptor. Every
relationship is checked: pipelines and runs own the task, events are contiguous
from sequence 1, artifact counts match the publication, and an artifact's
`sha256` matches its content-addressed key:

```text
v1/tasks/{taskId}/objects/sha256/{sha256[0:2]}/{sha256}
```

Each artifact descriptor contains its stable `artifactId`, owning `taskId` and
`runId`, producer `logicalPath`, public key, media type, byte size, SHA-256,
availability, and disclosure flags. Public keys are derived from these validated
fields; they are not caller-provided URLs.

### Complete trajectory descriptor

The trajectory endpoint returns a complete descriptor for the selected completed
run's immutable sanitized JSON artifact. It includes task, pipeline, run role and
state, start/end timestamps, exact duration, optional artifact ID, public key,
`mediaType: "application/json"`, byte size, SHA-256, `availability: "available"`,
and disclosure flags. It never returns partial records, cursors, prefixes, raw
ATIF, or a lossy transcript fallback. A task that is still active may expose its
completed planning trajectory while its lifecycle remains `active`; an
unavailable trajectory is represented by `null` in detail or a terminal `404`
from the descriptor route.

## Normalization from legacy data

### Performance

- Convert `schema_version` to the V2 envelope version.
- Convert source labels into unique implementation records.
- Convert each legacy row to one measurement with a stable ID.
- Convert MiB/s to bits/s using `value * 1024 * 1024 * 8`.
- Preserve requests/s, latency microseconds, elapsed milliseconds, utilization,
  versions, congestion control, failures, and artifact links.
- Legacy zero latency/request fields that are inapplicable to a scenario become
  `null`; genuine measured zero requires `status: "ok"` and metric applicability.
- Legacy `missing` sources become implementation availability, not fake rows.

### Interop

- Normalize `succeeded` to `pass`, `peer_broken` to `peer_failure`, and
  `known_peer_broken` to `known_peer_issue`.
- Create explicit lane and testcase IDs. Omitted matrix cells are
  `not_reported`; they are not silently synthesized as pass or unsupported.
- Preserve raw producer status and known-peer evidence.

### Coverage

- Preserve exact covered/total counts. Discard serialized percentages and derive
  them in consumers.
- Preserve component and least-covered-file order.

### Transcripts

- Preserve current public session IDs and original JSONL line ordering.
- Move pagination metadata into the shared page object.
- Treat archive availability as an artifact object rather than empty strings.

### Steward

- Cloud task status is `available`, `empty`, or `unavailable`; a valid empty
  publication is not an error or synthesized zero evidence.
- Visible D1 relationships are validated before normalization. A task page is
  complete within its bounded page; task detail validates exact expected counts,
  ownership, event sequence, run duration, artifact identity, and disclosure
  consistency before returning any field.
- Cloud envelopes use version `3.0`. The detail `trajectory` is either a complete
  validated descriptor for an available immutable JSON artifact or `null`; the
  reader does not expose partial ATIF/JSONL records, offsets, cursors, or raw
  transcript fallback.
- Artifact identity remains public and deterministic: `logicalPath` identifies
  the producer-declared artifact, while `publicKey` is the validated
  content-addressed R2 key. Both are returned with media type, byte size, digest,
  availability, and disclosure flags.
- D1 rows and R2 descriptors exclude credentials, private locators, scanner
  details, and private filesystem paths. The account-scoped D1 token never
  reaches a response or browser bundle.
- Complete ATIF validation, acquisition, normalization, API, rendering,
  activation, and proof remain owned by Plans 048, 049, and 051-056. Deployment
  Plan 060 owns old launch-wiring removal; this contract does not define those
  implementation or deployment steps.
- Convert loose external links and commit records to typed link/commit objects.
- Generate daily summaries in UTC from sanitized aggregate model-usage records
  and Git history. Never publish prompts, transcript content, or private paths.
- A model request is one non-null token-usage record. Daily token totals sum the
  final cumulative usage record from each CoQUIC session in the UTC window.
- `toolCalls` counts Codex `custom_tool_call` and `function_call` response
  records.
- Daily repository values cover commits on `main` during the complete UTC day.
  `changedLines` is `additions + deletions` for that boundary diff.
- `issuesResolved` counts GitHub issues closed during the UTC window. It does not
  infer a resolved issue from a commit subject or pull request.
- Daily validation counts completed engineering workflow runs. It excludes
  queued runs and `Steward Synthetic Monitor`; pass rate is derived from
  `validationsPassed / validationsCompleted` and is unavailable when no run
  completed.
- `live.observedAt` is the snapshot boundary. Tokens, requests, and tool calls
  cover the trailing `windowSeconds`; the home publication uses 60 seconds.
  `activeSessions` counts sessions with activity in the five minutes ending at
  that boundary. Repository and issue `*Today` values cover midnight UTC through
  the boundary. `validationsRunning` counts in-progress engineering workflows
  using the same exclusions as the daily validation total.
- Producers mark `live.availability` as `stale` when a snapshot has not refreshed
  within twice `windowSeconds`. Consumers retain stale values, label them as
  stale, and keep genuine zero distinct from `null` or an unavailable resource.
- Growth ranges end on the latest complete UTC day. `day`, `7d`, and `30d` are
  exact rolling calendar windows; `all` begins with the public repository.
  Every metric family publishes its own `coverage*StartDate`. A range is partial
  when any family begins after the selected boundary, and consumers MUST disclose
  that mismatch rather than extrapolate missing history.

## Cloud reader failure states and non-goals

The reader fails closed on invalid configuration, D1 transport/provider errors,
oversized or malformed responses, invalid public rows, dangling relationships,
unsafe object keys, and unavailable artifacts. It never returns a partial graph
or repairs publication data in the presentation layer. There is no local
SQLite/cache, sidecar, Worker, D1 mutation, raw filesystem scan, compatibility
reader, prefix/revision polling, or history migration.

Retired revision, global signal, and planner domains are unpublished by design.
Their cloud problem envelope is `schemaVersion: "3.0"`, `code: "UNAVAILABLE"`,
`status: 410`, and `retryable: false`. The response does not reflect route
parameters or private values.

## Content catalogs

Documentation, blog metadata, search entries, and Workbench scenarios MUST be
validated build-time data. A catalog entry contains stable ID, canonical route,
label/title, description, category, search keywords, and source path. Workbench
scenario entries additionally contain network defaults, supported controls, and
an ordered list of expected protocol milestones.
