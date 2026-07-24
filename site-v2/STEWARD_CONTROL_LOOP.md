# Steward Control-Loop Archive

Steward 2.0 publishes a raw control-loop archive beside the task archive.  It
is a research and recovery record, not a web control plane or a generated
aggregate dataset.  `$COQUIC_HOME/steward.sqlite` remains private operational
truth; only the roots below are public by placement:

```text
$COQUIC_HOME/control-loop/
  epoch.json
  current.json
  events/YYYY/MM/DD.jsonl
  planner-runs/<planner-run-id>/
```

The control-loop root and `$COQUIC_HOME/tasks/` share one immutable epoch ID,
UTC start time, and `post-steward-2.0` policy boundary.  Their format versions
are independent (`control-loop` currently `1.0`; the task archive has its own
version), so an evolution of one schema does not pretend that records have the
other archive's shape.  The archive starts at that epoch; it does not scan or
import pre-2.0 prompts, transcripts, signals, or legacy mirror files.

## Records and graph

Daily event files are append-only JSONL ledgers.  A record is published only
after its complete newline-terminated bytes and a monotonically allocated,
non-negative archive sequence are committed privately.  An accepted prefix is
never rewritten.  Recovery may discard only an unconfirmed incomplete final
line.  `current.json` is a bounded convenience projection and may be replaced
atomically; consumers reconstruct history from events and sealed planner runs.

Every normalized `SignalFetchRun` and every normalized `SignalItem` observation
has a stable opaque ID.  Repeated observations are retained even when their
provider/fingerprint deduplicates to one canonical signal.  Dedupe result and
canonical signal ID are explicit.  Canonical signal creation and status/link
transitions, normalized scheduler wakeups, daemon cycles/runtime transitions,
planner input IDs, proposal dispositions, and task edges are recorded.  The
causal graph is explicit in both directions:

```text
observation -> signal -> planner run -> proposal -> optional task
```

Edges use IDs, never timestamps, labels, payload matching, or consumer
inference.  A duplicate proposal records the covering task; rejected and
capacity-skipped proposals may have no task.  Invalid, policy-rejected,
capacity-skipped, failed, and interrupted work does not silently consume a
signal.

## Planner runs

A planner run is one global scheduler-planner `codex exec` process.  It is not a
task-local planning turn.  Every attempt receives a new private session home,
run ID, and Codex process.  Steward never resumes a scheduler planner, uses
`--last`, persists a `planner-thread.txt`, or carries a provider session ID
between cycles.  The daemon-owned planner container has no repository,
worktree, SQLite/WAL, Docker socket, daemon configuration, GitHub/SSH/sync
credential, or network authority.  A dedicated Codex API key is injected only
at the individual process boundary.

The prompt contains current pending normalized signals, active-task summaries,
allowed evidence IDs, and the output schema.  The only optional mount is the
read-only `planner-runs/` subtree of sealed prior runs.  History is untrusted
data and may be queried with read-only `rg`/structured reads for context or
deduplication; it cannot authorize a task, change policy, or replace a current
signal ID.

Every output proposal remains in ordinal order and has a bounded reason code
and one of `accepted`, `invalid`, `policy_rejected`, `duplicate`, or
`capacity_skipped`.  Accepted proposals link to a new or adopted task.  A
planner process/parse failure seals a failed run, leaves inputs pending, and
uses persisted bounded exponential backoff (30 seconds to five minutes by
default).  A later attempt is a distinct run and session; queued and active
task dispatch continues.

## Sealing and disclosure

Active prompt, transcript, result, session, activity, and telemetry bytes stay
under private runtime staging.  A terminal planner run is copied to a hidden
same-filesystem stage, descriptors are validated, and a terminal manifest is
written before atomic directory placement.  Every visible directory is
immutable and manifest-sealed.  The raw `codex.jsonl` file remains opaque and
may end with an incomplete final record; the event ledger never does.

Manifest descriptors cover every other regular file with relative safe path,
byte size, and lowercase SHA-256.  Startup reconciliation adopts exact sealed
bytes, repairs durable outbox lag, and rejects conflicting visible bytes or a
mismatched shared epoch.  Temporary filesystem errors set truthful lag and
retry asynchronously.  Only epoch/visible-byte conflicts set
`planning_blocked`; active task pipelines continue.  Private planner material
is deleted only after a public run directory and manifest have been
materialized and independently verified.

The archive intentionally preserves arbitrary normalized fields and raw text,
including synthetic credential-like values.  It does not capture provider HTTP
bodies/headers, transport credentials, SDK objects, daemon secrets, absolute
private paths, or private Codex homes.  There is no sanitization, redaction,
secret scanning, quarantine, approval, retention, compression, object storage,
or generated aggregate dataset.  An existing legacy sanitized mirror is inert:
Steward stops reading and writing it, and an operator may remove the exact
directory manually after identifying it.

Control-loop transfer is owned by Plan 009.  Site V2 import, SQLite indexing,
APIs, routes, and UI are owned by Plan 010; this contract performs no transfer,
request handling, deployment, or external mutation.
