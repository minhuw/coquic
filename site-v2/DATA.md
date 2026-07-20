# Canonical Data Contract

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
| Steward monitor        | `/api/v2/steward/status`                      | `steward.schema.json#/$defs/monitor`              |
| Steward daily summary  | `/api/v2/steward/daily/{date}`                | `steward.schema.json#/$defs/dailySummary`         |
| Steward growth summary | `/api/v2/steward/growth/current`              | `steward.schema.json#/$defs/growthSummary`        |
| Steward task           | `/api/v2/steward/tasks/{id}`                  | `steward.schema.json#/$defs/taskDetail`           |

The browser-local Workbench command/event protocol is defined by
`workbench.schema.json` and [WORKBENCH.md](WORKBENCH.md); it is not an HTTP API.

Stable legacy artifact and download paths MUST remain available during migration.
The V2 application SHOULD consume canonical endpoints so legacy transformation is
isolated in server adapters.

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

## Content catalogs

Documentation, blog metadata, search entries, and Workbench scenarios MUST be
validated build-time data. A catalog entry contains stable ID, canonical route,
label/title, description, category, search keywords, and source path. Workbench
scenario entries additionally contain network defaults, supported controls, and
an ordered list of expected protocol milestones.
