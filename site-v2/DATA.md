# Canonical Data Contract

The live dashboard and task summaries are not the source of control-loop
history.  Steward's durable raw control-loop peer is specified in
[STEWARD_CONTROL_LOOP.md](STEWARD_CONTROL_LOOP.md); it retains normalized
fetches, repeated observations, canonical signal transitions, planner
dispositions, and explicit graph edges.  The compact dashboard remains a
consumer-facing view and must not be treated as a sanitized producer or a
control plane.  Raw archive disclosure is by placement and is intentionally
not redacted.

## Envelope

Every first-party JSON response and static JSON artifact MUST use:

```json
{
  "schemaVersion": "2.0",
  "generatedAt": "2026-07-19T12:00:00Z",
  "data": {}
}
```

Collection responses MAY add `page`; generated evidence SHOULD add `provenance`.
HTTP errors use the problem object in `schemas/common.schema.json` and do not use
the success envelope.

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
| Steward dashboard      | `/api/v2/steward/dashboard`                   | `steward-dashboard.schema.json#/$defs/snapshot`   |
| Steward control loop   | `/api/v2/steward/control-loop`                | `steward-observability.schema.json#/$defs/controlLoop` |
| Steward monitor        | `/api/v2/steward/status`                      | `steward.schema.json#/$defs/monitor`              |
| Steward daily summary  | `/api/v2/steward/daily/{date}`                | `steward.schema.json#/$defs/dailySummary`         |
| Steward growth summary | `/api/v2/steward/growth/current`              | `steward.schema.json#/$defs/growthSummary`        |
| Steward task           | `/api/v2/steward/tasks/{id}`                  | `steward-observability.schema.json#/$defs/taskDetail` |
| Raw archive task list   | `/api/v2/steward/archive/tasks`              | `steward-dataset.schema.json#/$defs/taskListResponse` |
| Raw archive task detail | `/api/v2/steward/archive/tasks/{id}`         | `steward-dataset.schema.json#/$defs/taskDetailResponse` |
| Raw archive run         | `/api/v2/steward/archive/tasks/{id}/pipelines/{pipelineId}/runs/{runId}` | `steward-dataset.schema.json#/$defs/run` |
| Raw archive freshness   | `/api/v2/steward/archive/tasks/{id}/freshness` | importer status object                           |

The browser-local Workbench command/event protocol is defined by
`workbench.schema.json` and [WORKBENCH.md](WORKBENCH.md); it is not an HTTP API.

Stable legacy artifact and download paths MUST remain available during migration.
The V2 application SHOULD consume canonical endpoints so legacy transformation is
isolated in server adapters.

## Raw Steward task archive

The raw archive is an independent resource family, not another representation of
the sanitized Steward task. Its canonical source is the direct task tree defined
in [STEWARD_DATASET.md](STEWARD_DATASET.md), with epoch, task, pipeline, run,
validation, review, integration, and terminal-manifest metadata validated by
`schemas/steward-dataset.schema.json`. The archive is public by placement and
preserves raw bytes. It does not reuse the sanitized task schema or cache table.

The importer publishes execution state and archive state separately. A task may
be `succeeded` while `archiveState` is `live`, `incomplete`, or `corrupt`; only a
verified terminal manifest yields `archiveState: "verified"`. `lastSyncAt`,
`lastSuccessfulImportAt`, accepted byte offsets/prefix identities, and a stable
retry category describe freshness. Missing or partial usage and estimated cost
remain explicit objects with nullable values and reasons; zero is never a
placeholder for unavailable evidence.

Raw JSONL records are retained in source order and remain opaque. A progressive
consumer exposes only complete newline-terminated records. An incomplete live
tail is available as raw bytes but is not returned as a parsed record. Metadata
before an artifact, an artifact before metadata, a replacement, truncation, or a
missed watcher event is a recoverable import condition; the cache retries and
retains its last valid JSON view. Terminal hash or path mismatch after manifest
verification is corruption, not a partial success.

Site V2 keeps acquisition, normalization, domain state, and rendering separate.
The importer is a single asynchronous in-process Next.js owner. SQLite stores
only rebuildable cross-task metadata, aggregate facts, safe file descriptors,
accepted JSONL offsets, prefix identities, and bounded retry state; it never
stores transcript, prompt, patch, review, validation, or tool-output bodies.
Dashboard, history, aggregate usage/cost, freshness, and revision requests are
SQLite-only. A detail request may resolve one indexed task root and read one
selected file on demand. Missing and partial token/cost values remain distinct
from zero and every aggregate reports available-run coverage.

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

- Derive the dashboard snapshot from the sanitized monitor and retained task
  publications. It is a compact archive index, not a replacement for raw task
  evidence.
- Normalize the public control loop into three linked domains: signal evidence,
  planner decisions, and task execution. Preserve the IDs connecting each
  signal to its planner run and resulting task.
- Preserve planner output proposals separately from canonical accepted/proposed
  counters. When a run output contains tasks but the producer has no completion
  event, publish both values and a diagnostic; never silently reconcile them.
- Normalize task detail into five ordered stages: plan, implementation,
  validation, review, and integration. Every observed state transition carries
  a count, the contributing attempt IDs, and evidence-derived causes. Validation,
  review, or integration may return work to implementation.
- Task detail schema version 2.2 adds optional `planRuns` evidence with retry
  order, lifecycle timestamps, model settings, diagnostics, and transcript
  state. The structured `plan` remains the accepted output; planning runs do
  not imply one plan per implementation attempt.
- Preserve attempt-scoped worker and reviewer runs, parsed transcript records,
  patch statistics/content, validation commands/results/log availability,
  structured review findings/gaps, and the complete ordered event timeline.
- Every artifact declares availability, size, redaction, and truncation at its
  own boundary. A running task uses empty arrays or `null` for stages that have
  not produced evidence; it never synthesizes pending evidence as success.
- Exclude daemon and operator configuration, including integration policy,
  mutation limits, and timeouts. Observed queue occupancy and available source
  capacity remain working-state evidence rather than configuration disclosure.
- Preserve archive-wide task outcomes and artifact counts even when embedded
  recent task, signal, or wakeup lists are truncated. Published counts describe
  the embedded lists; totals describe the complete retained archive.
- Adapt public Steward schema v3 into the V2 envelope without reading private
  daemon state. Preserve the source compatibility state and truncation flags.
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

## Raw control-loop consumer

The raw control-loop peer is configured by
`COQUIC_STEWARD_CONTROL_LOOP_ROOT` and defaults to
`/opt/coquic-demo/steward/control-loop` only in production. It shares the task
epoch but has its own event-file generations and health. The disposable SQLite
cache stores normalized IDs, statuses, counts, graph edges, safe relative
locators, accepted complete-line byte ranges, manifest hashes, and bounded
retry state. It never stores event bodies, arbitrary normalized observation
objects, prompts, transcript records, planner output, diagnostics, or artifact
bytes.

Events are accepted only after newline termination and schema validation. An
append continues from its accepted prefix; truncation, replacement, duplicate
sequence, or malformed complete lines stage a replacement and retain the last
valid generation until the new file is valid. `current.json` is a freshness
hint and cannot erase event history. Planner-run directories are indexed only
after a schema-valid manifest covers every other regular file with exact size
and SHA-256. A later byte conflict is `archive-corrupt`.

Signals, observations, planner runs, proposals, and tasks join only through
producer IDs in explicit graph edges. Missing peers and dangling links remain
pending; an epoch mismatch is `incompatible` and does not merge or delete the
last compatible rows. Aggregate and pagination requests query SQLite only.
Selected signal events and planner transcripts/artifacts may read one
manifest- or cursor-verified raw file on demand. Every response preserves
missing, partial, pending, unavailable, incompatible, and corrupt states rather
than converting them to zero or empty success.

## Content catalogs

Documentation, blog metadata, search entries, and Workbench scenarios MUST be
validated build-time data. A catalog entry contains stable ID, canonical route,
label/title, description, category, search keywords, and source path. Workbench
scenario entries additionally contain network defaults, supported controls, and
an ordered list of expected protocol milestones.
