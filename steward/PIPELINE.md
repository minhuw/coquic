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
input tree, and expected identity. After the boundary it stores the result,
output tree, patch digest, and next cursor. Duplicate `advance_once()` calls
adopt a finished action or report `in_progress`; they do not repeat effects.

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
Successful task-owned work stops at durable `ready_to_seal`; lifecycle cleanup,
terminal sealing, and final sync belong to Plan 006.

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

The raw task synchronizer runs immediately after reconciliation and on a
monotonic 60-second cadence with no overlap. Its result is health-only. A
terminal task is sealed only after `ready_to_seal`, writer quiescence, and
external-action reconciliation. `cleanup_pending` is durable before container,
worktree, or private-home cleanup; `cleanup_complete` is written only after
every authorized action succeeds. The public archive remains intact.

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
