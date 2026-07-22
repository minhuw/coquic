# HTTP and Streaming Contract

## General HTTP behavior

- JSON media type: `application/json; charset=utf-8`.
- Problems: `application/problem+json` using RFC 9457-compatible fields.
- QA streaming: `text/event-stream; charset=utf-8` with buffering disabled.
- Dynamic evidence and status endpoints: `Cache-Control: no-store`.
- Immutable snapshot URLs MAY use long-lived public caching and immutable ETags.
- Dataset and raw transcript downloads include safe `Content-Disposition`.
- `HEAD` on dataset archives returns the same metadata headers as `GET` without a body.
- Successful responses include `X-Schema-Version: 2.0`.

## Status codes

| Status | Meaning                                                                |
| ------ | ---------------------------------------------------------------------- |
| 200    | Valid complete, partial, or empty resource. Inspect envelope metadata. |
| 400    | Invalid query/body syntax.                                             |
| 404    | Unknown safe resource identifier or unpublished artifact.              |
| 409    | Resource exists but cannot satisfy the requested state transition.     |
| 422    | Well-formed input that violates domain constraints.                    |
| 429    | Rate limited; include `Retry-After` when known.                        |
| 500    | Producer or transformation failure.                                    |
| 503    | Required backend/publication unavailable.                              |

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

## Steward

Steward endpoints are read-only. `GET /api/v2/steward/status` returns the latest
sanitized monitor publication. `GET /api/v2/steward/tasks/{id}` returns retained
task evidence. Artifact URLs are explicit and MAY return 404 when the publication
declares `notProduced` or `unavailable`; redacted artifacts have no URL.
Daemon and operator configuration is excluded from every public Steward payload.

`GET /api/v2/steward/control-loop` returns the linked public index used by the
Signals, Planning, and Tasks views. Signal records retain source context and link
to planner runs and tasks where those relationships exist. Planner runs retain
both canonical counters and parsed output proposals so incomplete producer state
is observable. Task summaries include the five pipeline stage states and declare
whether detail is published.

`GET /api/v2/steward/dashboard` returns a compact index derived from the monitor
and retained task publications. Archive totals cover the declared complete
archive even when recent task, signal, or wakeup lists are truncated. Raw task
publications remain authoritative for attempts, patches, transcripts,
validations, reviews, and event timelines.

`GET /api/v2/steward/daily/{date}` returns the UTC daily aggregate used by the
Home report. The date uses `YYYY-MM-DD`. Usage and repository groups declare
availability independently so a missing model-usage source never becomes zero.

## Raw Steward archive (future)

The raw archive endpoints are read-only and independent of the sanitized Steward
surface. They read the rebuildable importer cache; web requests never parse the
task tree directly.

`GET /api/v2/steward/archive/tasks` returns a V2 envelope whose `data` contains
the epoch identity, ordered task summaries, and importer freshness. Each summary
includes `taskId`, exact execution `status`, `archiveState` (`live`, `incomplete`,
`verified`, or `corrupt`), current pipeline ID, `updatedAt`,
`lastSuccessfulImportAt`, and a recoverable `importLag` object when bytes or
references are still converging. A task list does not imply terminal archive
verification.

`GET /api/v2/steward/archive/tasks/{taskId}` returns task detail grouped by
ordered pipeline. Each pipeline includes trigger, parent, phase/state, base/input
and resulting identities, validation and review descriptors, integration outcome,
and ordered runs. Run detail exposes role, role ordinal, stable archive session
ID, `resumeOfRunId`, parent/retry relations, model/reasoning, lifecycle/exit,
usage/cost availability, and artifact descriptors. A terminal task status and
the separate terminal-manifest verification result are both shown.

`GET /api/v2/steward/archive/tasks/{taskId}/pipelines/{pipelineId}/runs/{runId}`
returns the run metadata and artifact descriptors. Planning, implementation,
review, formality, commit-message, recovery, and other Steward-launched
`codex exec` processes are runs; deterministic validation and daemon Git/SSH
actions remain pipeline evidence. A resumed session is a new run and carries
`resumeOfRunId`.

`GET /api/v2/steward/archive/tasks/{taskId}/artifacts/{path}` returns the
synchronized raw bytes with the declared media type and safe content
disposition. It performs no normalization, redaction, or transcript
reconstruction. A live JSONL download may contain an incomplete tail, but parsed
record APIs exclude that tail and expose only the accepted complete-line prefix.

`GET /api/v2/steward/archive/tasks/{taskId}/freshness` returns `lastSyncAt`,
`lastSuccessfulImportAt`, watcher/reconciliation timestamps, accepted file
identity/prefix/size, retry category, and whether the terminal manifest is
observed, converged, verified, or corrupt. `GET /api/v2/steward/archive/tasks/{taskId}/import-status`
returns the same import state grouped by pending metadata, missing artifacts,
parse retries, and terminal verification. These are eventual-consistency
diagnostics, not a claim that transport is realtime.

## Legacy compatibility

During migration, these paths remain stable: `/perf-results.json`,
`/perf-history/index.json`, `/interop-results.json`, `/coverage-results.json`,
`/coverage/index.html`, `/duvet/report.html`, `/duvet/report.json`,
`/duvet/snapshot.txt`, `/steward/status`, `/steward/status.json`, transcript raw
downloads, and published dataset archive URLs.
