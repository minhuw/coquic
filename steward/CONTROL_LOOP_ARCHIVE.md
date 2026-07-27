# Control-loop archive

Steward writes the raw scheduler archive under `$COQUIC_HOME/control-loop/`.
The private SQLite ledger is the source of truth; the archive writer only
materializes ledger-confirmed bytes.

```text
control-loop/
  epoch.json
  current.json
  events/YYYY/MM/DD.jsonl
  planner-runs/<planner-run-id>/manifest.json
```

The control-loop epoch and `tasks/epoch.json` are allocated together.  Their
format versions are independent, but both carry the immutable epoch ID and
`post-steward-2.0` policy.  Steward does not scan, import, sanitize, redact, or
backfill pre-2.0 state.

## Write boundaries

Signal fetches, observations, canonical signal transitions, wakeups, cycles,
planner dispositions, and graph edges are committed in SQLite transactions.
Each committed event receives a monotonic sequence and an outbox row.  The
daemon-owned archive writer drains that outbox asynchronously.  A complete
newline-terminated event is never rewritten; only an unconfirmed incomplete
final line may be discarded during recovery.

Planner runs are sealed only after a terminal ledger disposition.  The writer
copies raw prompt, transcript, result, activity, telemetry, and tool-change
bytes to a hidden same-filesystem stage, writes a manifest with size and
SHA-256 descriptors, verifies it, and atomically places the directory.  A
visible run with different bytes or a different epoch blocks planning.  A
temporary filesystem failure leaves durable lag for retry and does not stop
active task pipelines.

The `current.json` file is a replaceable bounded projection.  Consumers must
reconstruct history from the event ledger and sealed planner runs.

## Planner isolation

Every scheduler planner attempt receives a fresh run ID, private session home,
and Codex process.  Steward never persists a planner thread handle, passes
`--last`, or resumes a provider session between cycles.  The planner boundary
has only read-only sealed `planner-runs/` history plus its own private output;
its locked Docker bridge supplies the outbound provider transport required by
`codex exec`.  It has no host networking, network-administration capability,
repository, worktree, SQLite database, Docker socket, daemon configuration, or
GitHub/SSH/sync credentials.

Planner output remains ordinal and records `accepted`, `invalid`,
`policy_rejected`, `duplicate`, and `capacity_skipped` dispositions.  Rejected
or failed output leaves source signals pending.  Failed attempts use persisted
bounded exponential retry (30 seconds through five minutes by default).

Raw control-loop transfer, Site V2 import, and APIs are separate concerns and
are intentionally not implemented by this archive writer.
