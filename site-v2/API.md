# HTTP and Streaming Contract

## General HTTP behavior

- JSON media type: `application/json; charset=utf-8`.
- Problems: `application/problem+json` using RFC 9457-compatible fields.
- QA streaming: `text/event-stream; charset=utf-8` with buffering disabled.
- Dynamic evidence and status endpoints: `Cache-Control: no-store`.
- Immutable snapshot URLs MAY use long-lived public caching and immutable ETags.
- Dataset and raw transcript downloads include safe `Content-Disposition`.
- `HEAD` on dataset archives returns the same metadata headers as `GET` without a body.
- Unrelated V2 responses retain their documented schema headers and versions.
  Steward cloud JSON bodies use `schemaVersion: "3.0"`; cloud routes do not
  expose a live credential or a private locator.

## Status codes

| Status | Meaning                                                                |
| ------ | ---------------------------------------------------------------------- |
| 200    | Valid complete, partial, or empty resource. Inspect envelope metadata. |
| 400    | Invalid query/body syntax.                                             |
| 404    | Unknown safe resource identifier or unavailable artifact.              |
| 409    | Resource exists but cannot satisfy the requested state transition.     |
| 422    | Well-formed input that violates domain constraints.                    |
| 429    | Rate limited; include `Retry-After` when known.                        |
| 500    | Producer or transformation failure.                                    |
| 503    | Required backend/publication unavailable.                              |
| 410    | A retired or unpublished cloud domain is intentionally unavailable.     |

## QA

`GET /api/v2/qa/suggestion` returns a suggestion envelope.

`POST /api/v2/qa/stream` accepts:

```json
{ "question": "How does ACK delay affect loss recovery?" }
```

Required headers: `Accept: text/event-stream`, `Content-Type: application/json`,
and an opaque `X-Session-ID`. The server emits named SSE events. Each `data:` line
is a JSON `streamEvent`:

- `metadata`: request ID, citations, and initial retrieval confidence.
- `answer.delta`: channel (`direct` or `grounded`), ordered sequence, text delta,
  and model when known.
- `answer.complete`: channel, final Markdown, model, and token usage.
- `complete`: accepted/rejected outcome, reason, final channel values, evidence.
- `error`: recoverable flag, stable code, message, and channels retained so far.

Sequence values are monotonic per channel. Consumers MUST ignore duplicates and
MUST NOT reorder deltas. A stream ending without `complete` or `error` is an
interrupted transport, not a completed empty answer.

## Transcript search

`GET /api/v2/transcripts` query parameters:

| Name       | Type    | Rule                                   |
| ---------- | ------- | -------------------------------------- |
| `q`        | string  | Trimmed, max 200 characters.           |
| `from`     | date    | Inclusive; defaults to manifest start. |
| `to`       | date    | Inclusive; defaults to manifest end.   |
| `page`     | integer | Minimum 1; defaults 1.                 |
| `pageSize` | integer | 1-100; defaults 25.                    |

Results are sorted by `startedAt` descending then `byteSize` descending then `id`.
Out-of-range pages clamp to the last valid page and report the canonical page.

`GET /api/v2/transcripts/{id}?cursor={opaque}&limit={1..200}` returns an ordered
record chunk. Cursors are opaque and scoped to the session. Reusing a cursor is
idempotent. Unknown sessions return 404; an expired/invalid cursor returns 400.

`GET /api/v2/transcripts/{id}/raw` returns the original JSONL bytes. The server
MUST NOT reconstruct a lossy transcript from normalized display records.

## Evidence

Current endpoints return validated canonical snapshots. History returns metadata
and snapshot URLs, not embedded full snapshots. Consumers fetch only required
snapshots and preserve index order.

Performance measurements are immutable within a snapshot. Interop result order
comes from `testcaseOrder`. Coverage collection order comes from the producer.

## Steward cloud reader

Steward cloud endpoints are read-only. Site V2 is a standalone Next.js Node
reader using server-side native `fetch` to Cloudflare D1 REST and anonymous
public R2. D1 reads join only `visible` task heads and visible publications;
staged, superseded, hidden, malformed, dangling, or private-shaped data fails
closed. The account-scoped D1 Read token is server-only because Cloudflare cannot
scope it to one database. No endpoint writes D1, runs a Worker/sidecar, opens a
local SQLite/cache, scans a filesystem archive, or serves a compatibility/history
fallback.

### Status and task pages

`GET /api/steward/status` returns a no-store `statusResponse` envelope:

```json
{
  "schemaVersion": "3.0",
  "generatedAt": "2026-07-28T00:00:02Z",
  "data": {
    "state": "available",
    "taskCount": 1,
    "latestPublicationAt": "2026-07-28T00:00:01Z"
  }
}
```

`state` is `available`, `empty`, or `unavailable`; an empty visible publication
is a valid response and is not fake success. `GET /api/steward/tasks` accepts
`scope=active|history` (default `history`), `limit` (default 50, bounded to
1-50), and an opaque scope/publication-bound `cursor`. It returns a `3.0`
`taskPageResponse` whose `data.items` are complete task summaries and whose
`data.pagination` has `page`, `pageSize`, `total`, and `hasNextPage`. Cursor
continuations are also exposed in `X-Steward-Next-Cursor` and
`X-Steward-Previous-Cursor`; a stale cursor is a terminal `409`.

Each summary contains `taskId`, title, lifecycle state (`active`, `completed`,
`failed`, or `cancelled`), timestamps, `completeness: "complete"`, owning
pipeline and completed-run IDs when present, event/artifact counts, and public
disclosure flags. Active tasks remain separate from terminal history, including
an active task that already has a completed planning run.

### Task detail and trajectory

`GET /api/steward/tasks/{taskId}` returns a no-store `3.0` `taskDetailResponse`.
Its `data` is an all-or-nothing graph of `task`, `pipelines`, `runs`, ordered
`events`, `artifacts`, and nullable `trajectory`. The reader validates exact
publication counts, ownership, contiguous event sequence, run duration, artifact
SHA-256/public-key identity, and disclosure consistency before serializing the
graph. Unknown or hidden tasks return `404`; malformed IDs return `400`.

`GET /api/steward/tasks/{taskId}/transcript?run={runId}` resolves the visible
selected run, verifies its immutable sanitized R2 ATIF object once, and returns
the complete normalized trajectory. Success is a no-store `4.0`
`completeTrajectoryResponse`; `data` is the closed display model with every
validated step, tool call, observation, multimodal part, disclosure flag, and
same-origin artifact action. It never returns raw ATIF, a descriptor/public R2
key, private-original locator, partial records, prefixes, cursors, or a lossy
fallback. An omitted `run` selects the visible completed trajectory; an
explicit run must be completed and publicly available.

Transcript failures are value-free no-store `3.0` problem envelopes: invalid
selectors are `400`, absent/hidden/unavailable selections are `404`, bounded
resource rejection is `413`, D1/R2 integrity, schema, or ownership rejection is
`422`, and transient D1/R2/network/timeout/5xx failures are `503`. Only `503`
is retryable by the reader; none of these cases exposes upstream diagnostics or
accepts a caller-supplied URL.

### Artifact action

`GET /api/steward/tasks/{taskId}/artifact?path={logicalPath}` validates the task
ID and relative logical path, resolves the D1 artifact descriptor, derives the
content-addressed public R2 URL below the configured anonymous base, and returns
one empty `307 Temporary Redirect`:

```text
v1/tasks/{taskId}/objects/sha256/{sha256[0:2]}/{sha256}
```

The same-origin Site action sets `Location`, `Cache-Control: no-store`,
`Content-Type: application/octet-stream`, and `X-Content-Type-Options: nosniff`.
It never proxies bytes and ignores caller-supplied URL parameters. Invalid paths
return `400`; missing or unavailable artifacts return `404`; unsafe public data
or cloud failures return a problem response without reflecting private values.

## Retired cloud domains and errors

The revision and global signal/planner archive domains are unpublished in the
cloud contract. Each of these routes returns the same no-store `410` problem and
never reads D1 or R2:

- `GET /api/steward/revision`
- `GET /api/steward/signals/{signalId}/events`
- `GET /api/steward/planner-runs/{plannerRunId}/transcript`
- `GET /api/steward/planner-runs/{plannerRunId}/artifacts/{artifact}`

The body is a `schemaVersion: "3.0"` `problemResponse` with
`code: "UNAVAILABLE"`, message `The global archive domain is unavailable in the
cloud contract.`, `retryable: false`, `status: 410`, and `type: null`. Route
parameters, query strings, credentials, and private values are never reflected.

Cloud route problem categories are closed and non-diagnostic:

| Code | Status | Retryable | Meaning |
| ---- | ------ | --------- | ------- |
| `INVALID_REQUEST` | 400 | no | Invalid identifier, logical path, scope, or limit. |
| `INVALID_CURSOR` | 400 | no | Cursor encoding or scope is invalid. |
| `STALE_CURSOR` | 409 | no | Cursor no longer names the visible publication. |
| `NOT_FOUND` | 404 | no | Task, run, or artifact is not published/available. |
| `RESOURCE_LIMIT` | 413 | no | A bounded cloud or transcript resource was rejected. |
| `MISCONFIGURED` | 503 | no | Required server cloud value is missing or unsafe. |
| `INTEGRITY_FAILURE` | 503 | no | Visible D1/R2 data fails public validation. |
| `RATE_LIMITED` | 429 | yes | Cloudflare rate-limited the read. |
| `UNAVAILABLE` | 503 | conditional | D1 network/timeout/server failures may retry; provider, authorization, malformed, HTTP, or limit failures are terminal. |

Only transient `RATE_LIMITED` and retryable `UNAVAILABLE` responses offer a
manual Retry action. No cloud route automatically polls, retries, falls back to
partial data, or repairs a publication in the UI.

The transcript route's `422` integrity and `503` transient policy above is more
specific than these shared legacy categories; unrelated cloud routes retain
their documented status mappings.

## Legacy compatibility

Unrelated legacy artifact paths remain stable during migration: `/perf-results.json`,
`/perf-history/index.json`, `/interop-results.json`, `/coverage-results.json`,
`/coverage/index.html`, `/duvet/report.html`, `/duvet/report.json`,
`/duvet/snapshot.txt`, transcript raw downloads, and published dataset archive
URLs. Steward cloud routes above are the sole task reader; there is no raw
archive compatibility reader or historical migration.
