# Steward Task Pipeline

Steward treats one task as a durable source record containing an ordered set of
bounded pipelines. The initial pipeline is allocated with the task. Repairs,
integration rebases/conflicts, and push races create child pipelines under the
same task; they never create synthetic integration-manager tasks.

## Cursor

The normalized ledger keeps the Plan 002 coarse phase for compatibility. The
executor records the finer cursor and action identity in ordered events and
phase artifacts:

`provisioned -> planning -> implementation -> validation -> review -> formality
-> integration -> commit_message -> commit -> push -> ready_to_seal`.

Planning is required for feature work. A narrowly scoped fix records a stable
skip reason. Validation is deterministic and runs the complete gate set. Every
planning, implementation, review, formality, and commit-message action starts a
fresh Plan 003 session. Ordinary repair paths never resume a provider session.

Before an external boundary Steward stores task, pipeline, phase, action, base,
input tree, and expected identity. Each task also carries a Store-owned
`execution_mode` latch in its existing metadata JSON; missing latches adopt the
startup `dry_run` setting, live may tighten to dry-run, and a later live startup
never unlocks dry-run. After the boundary it stores the result, output tree,
patch digest, and next cursor. Duplicate `advance_once()` calls adopt a
finished action or report `in_progress`; they do not repeat effects.

Dry-run admission is fail-closed at every external seam. Local planning,
validation, commits, and archive materialization may complete, while blocked
external actions are retained as typed proposal evidence. Terminal dry-run tasks
are sealed and verified locally, disposable resources are removed, and the
archive remains private. Planner-selected signals stay atomically
preview-covered by their task; no dry-run record enters the publication outbox
or Site V2. Set `dry_run = false` at startup to opt into live publication.

A live transition is explicit rather than an automatic replay. After restart in
live mode, `coquic-steward rerun-live <dry-run-task-id>` verifies the source's
terminal status, non-applied effect evidence, retained archive, and current
signal identities before allocating a new task and initial pipeline. Linked
signals are revalidated immediately before the transaction; stale signals are
omitted, mixed selections retain only actionable identities, and provider
uncertainty or an all-stale selection is side-effect-free. Manual tasks with no
linked signals are allowed. The source task and archive remain immutable, old
proposals and execution artifacts are never inputs, and the command only
queues—the daemon later rereads current repository/provider state. One active
live descendant is allowed per dry-run source.

## Review Formality

The raw reviewer JSON is immutable evidence. A fresh read-only formality
examination maps every finding index exactly once to `required`, `revert`,
`followUp`, `reject`, or `escalate`. Required/revert findings create a fresh
review-repair pipeline. Escalation, malformed output, and exhausted budgets
block. Follow-up proposals are archived as inert structured evidence and do
not create issues, tasks, comments, or other external work.

## Integration And Push

Integration runs under the global integration lock, fetches the latest `main`,
and proves the accepted patch/tree identity before commit. Any base movement
creates an `integration-rebase` child and repeats validation and review.
Apply conflicts create an `integration-conflict` child with bounded evidence.
Push uses no force option. A true non-fast-forward result creates a `push-race`
child; bounded transient transport failures may retry the same commit.

Only the trusted daemon stages, commits, and pushes. Immediately before commit,
the staged tree must equal the last validated and effectively reviewed tree.
Successful task-owned work stops at durable `ready_to_seal`; terminal sealing
records an orthogonal external-effect result (`not-applicable`, `not-applied`,
or `applied`) before lifecycle cleanup. Dry-run cleanup retains the verified
private archive while removing disposable resources; live publication and its
cleanup fencing remain unchanged. A live rerun gets a fresh task identity and
lineage metadata; it is not another repair pipeline under the source task.

## Daemon lifecycle

Startup reconciles the normalized execution ledger, archive generations,
worktree checkpoint, container labels, wrapper identity, and local/remote Git
ancestry in task-id order. Matching live wrappers are adopted and complete
atomic results are ingested once. Missing processes become interrupted evidence;
only an interrupted planning, implementation, or review run with an exact
checkpoint may resume by its persisted provider session ID. Resume is limited
to two transient launch attempts, then a fresh recovery session receives a
bounded packet pointing at the complete task-owned transcript/diff and inline
tails. Provider IDs and private homes never enter prompts or public metadata.

Workers advance one durable phase at a time in a bounded pool. A stopping
daemon rejects new claims, cancels wrappers and subprocesses, waits the bounded
grace, and stops (without removing) all owned containers. State is retained for
restart and active tasks are not marked failed or sealed by shutdown.

Startup verifies the private task and control-loop projections before dispatch.
Later projection work is asynchronous and wakeup-driven; sanitized cloud
publication is a separate daemon-owned operation. Raw task and control-loop
archives remain private. Verified public objects remain, while an exact private
terminal task archive is removed only through a durable, verified cleanup
transaction.

When operated through Docker Compose, this lifecycle remains the sole owner of
shutdown, reconciliation, and terminal cleanup. Compose supervises only the
trusted daemon service; task and planner siblings have `restart=no` and are
adopted by exact ledger/image/epoch labels. A Compose stop preserves stopped
containers and session evidence. The finalization call removes an exact
stopped container immediately after sealing and verification, then records
`cleanup_complete`; it does not wait for a periodic garbage collector.

## Budgets

Pipeline, run, validation, review, formality, transport, and no-progress
fingerprint budgets are explicit. Repeated patch/failure/finding fingerprints
block rather than loop. Every archive artifact is bounded and excludes private
provider identifiers, credentials, and session-home paths.
