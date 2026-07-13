# 01 - Public Monitoring Contract

Status: Complete
Dependencies: 00
Can run in parallel with: Nothing; it unlocks the main workstreams.

## Objective

Define schema version 3 for the site-facing Steward monitoring data before
producer or consumer implementations diverge.

## Contract Additions

- A `runtime` object with daemon instance ID, process start time, heartbeat
  time, current state, current cycle start, and last completed cycle summary.
- A `publication` object describing snapshot generation and producer-side
  publish health without exposing host paths or credentials.
- A bounded standalone planner-run collection with sanitized diagnostics and
  artifact descriptors.
- Explicit artifact availability and truncation fields.
- Stable enums for live state, publish state, and compatibility state.

## Version And Compatibility

The public status document is a JSON object with `schema_version: 3`. The
producer must reject an unsafe configuration before writing a public document;
the site must decode only the top-level version and required envelope fields
before reading optional sections.

The decoder uses these rules:

| Version | Consumer behavior |
| --- | --- |
| `3` | Decode required fields. Ignore unknown additive fields. |
| `0` or `1` or `2` | Treat as unsupported legacy data and render `incompatible`. |
| Greater than `3` | Treat as `incompatible` until a compatible decoder is deployed. |
| Missing, non-integer, or malformed | Treat as `incompatible`; preserve the last valid snapshot when available. |

`compatibility_state` is one of `compatible`, `unknown_additive`, or
`incompatible`. The producer writes `compatible`; the site may use
`unknown_additive` when it successfully decodes version 3 while retaining
unknown fields. It must never infer compatibility from a task or publication
state.

All timestamps are UTC ISO 8601 strings with an explicit `Z` suffix. IDs,
commit SHAs, repository names, and enum values are opaque public identifiers;
they must not contain local paths, credentials, prompt text, thread IDs, or
hostnames.

## Required Envelope

The following fields are required. `state` is the aggregate task state kept for
backwards-readable dashboard summaries; daemon liveness is represented only by
`runtime` and its heartbeat age.

```json
{
  "schema_version": 3,
  "compatibility_state": "compatible",
  "generated_at": "2026-07-13T12:00:00Z",
  "repository": "minhuw/coquic",
  "main_branch": "main",
  "state": "idle",
  "counts": {},
  "runtime": {},
  "publication": {},
  "tasks": [],
  "signals": {},
  "scheduler": {},
  "planner_runs": [],
  "audit": [],
  "configuration": {},
  "integration": {}
}
```

Required enum values are:

- `state`: `idle`, `queued`, `working`, or `attention`.
- `runtime.state`: `starting`, `idle`, `active`, or `stopping`.
- `publication.state`: `disabled`, `pending`, `published`, or `failed`.
- `compatibility_state`: `compatible`, `unknown_additive`, or
  `incompatible`.
- `planner_runs[].status`: `running`, `succeeded`, `failed`, or `invalid`.

## Runtime Object

`runtime` is required even when the daemon has not completed a task:

| Field | Type and rule |
| --- | --- |
| `instance_id` | Required non-secret daemon instance identifier. It changes on every process start and is not a filesystem path. |
| `started_at` | Required UTC timestamp for this daemon process. |
| `heartbeat_at` | Required UTC timestamp updated independently of task changes. |
| `state` | Required live-state enum. `active` means a cycle or dispatch is in progress; `idle` means the daemon is alive but has no active cycle. |
| `current_cycle_started_at` | UTC timestamp or `null`. Required when `state=active`; `null` otherwise. |
| `current_cycle_reason` | Bounded public reason or `null`; never a prompt or exception string. |
| `last_completed_cycle` | Object or `null`, described below. |
| `heartbeat_interval_seconds` | Positive integer producer interval, bounded to 5..60. |

`last_completed_cycle` has required `completed_at`, `reason`, and `result`
fields. `result` contains only non-negative integer counts: `recovered`,
`signal_fetches`, `signal_items`, `new_signal_items`, `planned`, `enqueued`,
`dispatched`, and `skipped`.

## Publication Object

`publication` describes local producer state and the last accepted snapshot;
it never contains the SSH user, host, key, known-hosts path, command line, or
remote path.

| Field | Type and rule |
| --- | --- |
| `state` | Required publish-state enum. `published` means the most recent snapshot was accepted by the configured target; `failed` is observable but does not stop daemon work. |
| `snapshot_id` | Required SHA-256-like lowercase hex digest for the generated snapshot, or `null` when no snapshot exists. |
| `generated_at` | Required UTC timestamp for the current snapshot. |
| `last_attempt_at` | UTC timestamp or `null`. |
| `last_success_at` | UTC timestamp or `null`. |
| `last_failure_at` | UTC timestamp or `null`. |
| `last_failure_category` | `ssh_preparation`, `rsync_transfer`, `timeout`, `serialization`, `permissions`, or `unknown`, or `null`. Raw command output is never allowed. |
| `retry_count` | Non-negative integer capped at 10. Reset to zero after success. |
| `last_accepted_digest` | Digest accepted by the remote target, or `null`. |

When public publishing is disabled, `state=disabled`, failure and retry fields
are `null`/`0`, and daemon runtime data remains valid. A failed publication
must not change task status or scheduler ownership.

## Bounded Collections

The producer emits newest-first arrays with these hard maximums. A collection
may contain fewer records; it must never exceed its bound. A corresponding
`*_truncated` boolean is required for each collection where an older record
may have been omitted.

| Collection | Maximum | Truncation field |
| --- | ---: | --- |
| `tasks` | 80 | `tasks_truncated` |
| `signals.items` | 80 | `signals.items_truncated` |
| `signals.fetches` | 40 | `signals.fetches_truncated` |
| `scheduler.pending_wakeups` | 20 | `scheduler.pending_wakeups_truncated` |
| `scheduler.recent_wakeups` | 20 | `scheduler.recent_wakeups_truncated` |
| `planner_runs` | 40 | `planner_runs_truncated` |
| task `events` | 200 | `events_truncated` |
| task `attempts` | 40 | `attempts_truncated` |
| task `plan_runs` | 40 | `plan_runs_truncated` |
| task `validations` | 40 | `validations_truncated` |
| integration `runs` | 8 | `runs_truncated` |
| recursive diagnostic arrays | 40 | enclosing artifact `truncated` |

The producer may use a smaller operational window, but it must keep the
published limit stable and set the truncation flag when more records exist.
The site must display an explicit truncated state rather than implying that a
collection is complete.

## Planner Run And Artifact Contract

Each `planner_runs[]` record is a standalone signal-planner iteration, not a
task implementation-plan run. Required fields are `id`, `status`, `started_at`,
`completed_at`, `accepted_count`, `proposed_count`, `consumed_signal_ids`,
`diagnostics`, and `artifacts`.

`diagnostics` is a bounded object containing only `summary`, `exit_code`,
`error_category`, and `last_message_present`. `error_category` is one of
`none`, `timeout`, `invalid_output`, `provider_error`, or `execution_error`.
`consumed_signal_ids` is capped at 40 and contains public signal IDs only.

Every artifact is either `null` (not produced or unavailable) or an object:

```json
{
  "availability": "available",
  "mode": "redacted",
  "text": "bounded sanitized text",
  "size_bytes": 1234,
  "original_size_bytes": 1234,
  "truncated": false,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

`availability` is `available`, `not_produced`, `unavailable`, or `redacted`.
`mode` is `none` or `redacted`; `raw` is not a public contract value.
`text` is at most 64 KiB for transcripts/diagnostics, 24 KiB for last
messages, and 128 KiB for patches. `original_size_bytes` is included only
when it can be measured without exposing a private path. `sha256` is optional
for redacted text and must be absent for unavailable artifacts. A URL is
allowed only when the producer marks it safe and it points to an approved
HTTPS repository path.

## Redaction And Link Rules

- Public mode accepts only `transcript_mode=none` or bounded `redacted`.
  `raw` is rejected before serialization.
- Prompts, raw transcripts, thread IDs, local paths, environment values,
  credentials, SSH arguments, and private-key-name fragments are never
  emitted, including recursively nested diagnostics and metadata.
- Links are emitted only for approved HTTPS hosts and known repository paths;
  local file URLs, arbitrary hosts, query-bearing credential links, and
  unvalidated paths are omitted.
- Missing, redacted, not-produced, unavailable, and truncated artifacts are
  distinct states. Consumers must not turn any of them into an empty success.

## Representative Fixtures

The checked-in fixtures under `steward/schema/fixtures/public-monitor-v3/`
cover `idle`, `active`, `failed`, `stale`, and `empty` states. They are
deterministic, contain no private paths or seeded secrets, and are the shared
input for producer validation and generated site decoder tests in subplans 05
and 13.

## Decisions

- The site remains read-only and consumes only published data.
- Unknown additive fields are tolerated within schema version 3 and reflected
  as `unknown_additive` by a consumer that chooses to expose that detail.
- Unknown major schema versions render an incompatible-data state and must
  preserve the last valid snapshot rather than clearing the monitor.
- Runtime timestamps use UTC ISO 8601 values.
- Public raw transcript behavior is excluded from this contract.

## Validation

- Add representative JSON examples for idle, active, failed, stale, and empty
  repositories. See `steward/schema/fixtures/public-monitor-v3/`.
- Review every field against the redaction policy from subplan 00.
- Confirm field limits for tasks, signals, fetches, planner runs, and artifacts.

## Done When

Producer and site owners can implement against one reviewed field-level
contract without reading each other's internal models.

Suggested commit: `docs(steward): define public monitor schema v3`
