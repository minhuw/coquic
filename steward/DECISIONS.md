# Steward decisions

## Static dispatch and boundary adapters

Steward business methods are invoked through one statically dispatched contract.
Internal publication values are the concrete current types, mappings, and
owner-detached values explicitly accepted by each boundary; method-bearing
lookalikes are not a compatibility surface. Mapping traversal and typed
reflection over data fields remain valid because they do not select executable
business behavior.

Only an unavoidable third-party boundary may use a narrow, named adapter for a
pinned provider shape. Such adapters must fail explicitly rather than discover
serializers or search arbitrary object graphs. Publication conversion preserves
canonical bytes, digests, redaction, mutation detection, limits, and bounded
failure categories while rejecting unsupported values without executing their
methods.

Publication-envelope validation and both metadata digests belong to the
transport-neutral envelope contract. The contract preserves schema 2.0,
allowlists, detached output, replacement semantics, and the six bounded
categories (`invalid_request`, `private_value`, `generation_conflict`,
`generation_state`, `count_mismatch`, and `digest_mismatch`). D1 maps those
categories at its pre-transport boundary; it retains provider-specific errors
and the independently owned Steward-overhead math and digest, whose canonical
bytes intentionally have no trailing newline.

Later architecture plans share ownership of this decision log.

## Explicit Store initialization

Production startup is the migration-free `bootstrap → init → start` sequence.
Bootstrap verifies the repository, credentials, and selected release without
creating SQLite. `coquic-steward init` is the sole intentional production Store
creation entry point: it runs stopped, opens an exact existing current Store for
idempotent repeats, and refuses invalid or mismatched state without repair.
Ordinary CLI loads disable legacy migration and open the exact Store; start
validates it before launching Compose. Recovery and daemon restart own no hidden
initialization transition.

## Ledger-owned task execution

Every current task has one persisted execution row and one valid owning pipeline.
This ledger-owned execution boundary is consumed directly by execution, session,
run, checkpoint, archive, and dispatch paths; missing or invalid ownership must
fail closed.
Consumers never infer a pipeline from elapsed time, row order, synthetic IDs, or
create-on-read repair, and failure handling does not finalize or mutate task
evidence while ownership is corrupt.

## Retired publication build timeout

Strictly reject retained `build_timeout_seconds` keys; removal before upgrade
is required, and key-free configuration remains compatible with the previous
release for rollback. There is no warning, alias, rewrite, migrator, timer, or
runtime deadline. Existing scanner/OCR, network, lease, retry, and task-stage
timeouts remain separate. Any future deadline requires an explicit cross-caller
deadline, cancellation/cleanup, and failure/retry contract.
