# Raw Steward Task Archive

This document defines the public-by-placement archive contract for Steward 2.0.
It is a separate raw research channel from the sanitized Steward publication
described in `DATA.md`, `API.md`, and the existing Steward schemas. The archive
is useful for crash recovery, direct mirroring, and progressive Site V2 import;
it is not a generated dataset projection.

## Boundary and ownership

The producer's canonical archive root is `$COQUIC_HOME/tasks/`. The Site V2
machine contains the same relative tree below its configured tasks root. There
is one immutable `post-steward-2.0` epoch at `tasks/epoch.json`; only task
directories created after that epoch starts are eligible. No legacy task,
transcript, plan, iteration, or human-assisted archive is copied or backfilled.

`$COQUIC_HOME/steward.sqlite` remains the private operational ledger and
`$COQUIC_HOME/worktrees/<task-id>/` remains disposable execution state. Neither
is part of this archive. A completed task directory is understandable without
SQLite or its worktree.

Anything durable and non-hidden below `tasks/` is intentionally public. Raw
prompts, transcripts, commands, source excerpts, and credential-like strings
are preserved byte-for-byte; they are not sanitized, redacted, scanned,
filtered, quarantined, or approval-gated. This disclosure rule does not permit
daemon credentials, Codex session homes, auth payloads, SSH/GitHub configuration,
Docker state, SQLite/WAL files, global logs, caches, locks, sockets, temporary
files, worktrees, build outputs, publisher health, or another task below the
archive root. Placement, rather than content inspection, is the disclosure
boundary.

This is the explicit publish-by-placement rule: placement below a task makes
durable evidence public, while private operational state stays outside.

## Canonical tree

The task hierarchy is stable and uses validated opaque IDs as directory names:

```text
<tasks-root>/
  epoch.json
  <task-id>/
    task.json
    prompt.md
    events.jsonl
    pipelines/<pipeline-id>/
      pipeline.json
      inputs/
      patches/
      validations/<validation-id>/validation.json
      validations/<validation-id>/output.log
      reviews/
      runs/<run-id>/
        run.json
        prompt.md
        codex.jsonl
        activities.jsonl
        telemetry.json
        last-message.md
        result.json
        tool-changes/manifest.jsonl
        tool-changes/summary.json
    manifest.json
```

Optional artifacts are described by an artifact object in their owning metadata;
absence is explicit and is not represented by an invented empty file. A producer
and its mirror use these same forward-slash relative paths. There is no second
`raw-dataset/current`, revision tree, archive bundle, sanitized projection,
content-addressed copy, root revision manifest, live global manifest, snapshot
ID, or publication ordering contract.

## Epoch, task, pipeline, and run vocabulary

The epoch record contains an opaque `epochId`, format version, UTC start time,
and the `post-steward-2.0` policy. `task.json` contains the original prompt and
events paths, exact Steward task status vocabulary, timestamps, current pipeline,
summary, and ordered pipeline descriptors. The task status is the execution
status observed by Steward; `succeeded` or another terminal status does not by
itself mean the archive is verified.

A pipeline is one bounded processing pass. It has a stable ID, task ID, ordinal,
trigger, optional parent pipeline, input/base identity, output/patch identities,
phase, state, timestamps, validation/review/integration descriptors, and ordered
run descriptors. The allowed triggers are `initial`, `validation-repair`,
`review-repair`, `integration-rebase`, `integration-conflict`, and `push-race`.
A phase is one of `planning`, `implementation`, `validation`, `review`,
`integration`, or `complete`; a pipeline state is `active`, `succeeded`,
`failed`, `blocked`, `cancelled`, `interrupted`, or `superseded`.
A repair or base change creates a child pipeline; a daemon restart does not.

A run is exactly one Steward-launched `codex exec` process. Planning,
implementation, review, formality examination, commit-message generation,
recovery launches, and every other Steward-level retry are separate runs. Each
run has a unique ID, open role string, positive role ordinal, directory,
transcript and result evidence. Deterministic validation and daemon Git/SSH
actions are pipeline evidence, not runs.

A session is a logical Codex conversation. Ordinary role launches use a fresh
session. Only recovery from an interrupted planning, implementation, or review
run may resume its session. A resumed process is always a new run with a
`resumeOfRunId` pointing to the interrupted run; normally a session has one run
and exceptionally an ordered recovery chain. Public metadata exposes the stable
archive session ID and never exposes a provider thread/session ID, private
Codex-home path, or recovery credential. Raw `codex.jsonl` remains opaque and
may contain an unmistakably synthetic or provider-issued identifier naturally.

The initial pipeline exists before optional planning, so a planning run has a
natural parent. Malformed output or a lost invocation creates another run in the
same pipeline and normally starts a fresh session. A repair that changes the
patch or base starts a child pipeline and fresh sessions.

## Live publication

Active task publication is deliberately eventually consistent. There is no live
global revision, snapshot manifest, ordering guarantee, or atomic multi-file
commit. A consumer must tolerate a file, directory, or metadata reference
arriving before or after related bytes and must preserve its last valid cached
state while the tree converges. Transport ordering has no semantic meaning.

Producers atomically replace small JSON/Markdown metadata files while live,
append to JSONL only, never rewrite a published JSONL prefix, use stable paths,
never reuse an ID, and never delete or rename visible task evidence. Completed
runs and pipelines are immutable. Temporary names are hidden and never
contractual.

The importer state machine is:

1. Discover a task directory and `task.json` even when no manifest exists.
2. Accept only a complete schema-valid JSON document and retain the last-valid
   JSON cache on absence or parse failure. Retry after file events and periodic
   reconciliation.
3. For JSONL, consume only newline-terminated records. Ignore an incomplete
   final record, remember the accepted byte offset and prefix identity, and
   import appended records idempotently. This complete-line rule is the only
   parsed-record boundary. A replacement, truncation, or changed
   accepted prefix causes a bounded per-file rebuild rather than duplicate rows
   or silent history loss. Unknown Codex and observation record shapes remain
   opaque raw records; they are never normalized by this contract.
4. Treat missing or cross-version references, metadata-before-artifact,
   artifact-before-metadata, and a manifest arriving before its content as
   recoverable live inconsistency. Retry until the tree converges while keeping
   the last valid cached state.
5. Run a periodic reconciliation scan after missed or coalesced filesystem
   events and after watcher restart. Watcher events are latency hints, not
   recovery truth.
6. Distinguish a terminal task status observed in `task.json` from a terminal
   archive verified by `manifest.json`.

## Terminal freeze and verification

Steward first reaches a terminal task outcome, finalizes every task-owned
external result, closes and freezes the directory, and writes one immutable
task-local `manifest.json`. The manifest is terminal-only integrity evidence,
not a live publication commit point. It contains the epoch/task/completion
identity and a canonical list of every durable regular file under the task
directory except itself, with exact relative path, byte size, and lower-case
SHA-256. No hidden file, symlink, directory, socket, or other non-regular file
is a descriptor.

Rsync or another transport may deliver the terminal manifest before referenced
bytes. Site V2 marks an archive complete only when every descriptor exists and
verifies; otherwise it remains live/incomplete and retries. After verification,
any source mutation is archive corruption. No transport ordering is required.

The Site V2 cache stores file identity, accepted prefix/size, parse status, and
retry state. Aggregate/list requests read SQLite only and never scan multiple
raw task directories. A task-detail request first resolves one indexed task ID
and may read metadata or selected accepted evidence from that one task
directory. Raw artifact downloads return synchronized bytes without
normalization; parsed transcript chunks stop at the accepted newline boundary
and incomplete live tails are not returned as parsed records. The cache is
disposable and is never a second raw payload projection.

## Paths, records, and disclosure

Paths are safe forward-slash relative paths built from validated opaque IDs.
Reject absolute paths, `.`, `..`, backslashes, NUL, hidden temporary names,
symlinks, and non-regular artifact files. The raw bytes themselves may contain
arbitrary strings, including harmless absolute paths or synthetic
credential-like values; those contents are not path-policy inputs.

Usage and cost availability are explicit. Usage may be available, partial, or
unavailable, with nullable token fields and a stable reason. Estimated cost is
an integer micro-USD value with model and pricing provenance; unavailable cost
must retain its reason and must never be converted to zero.

The JSON Schema in `schemas/steward-dataset.schema.json` defines the structural
contract. It deliberately does not define an arbitrary Codex JSONL record
schema. The running and complete trees in `examples/steward-dataset/` are
synthetic fixtures for producer and importer tests, not a generated dataset.
