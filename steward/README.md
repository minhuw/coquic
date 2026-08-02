# CoQUIC Steward

Steward is the local maintenance scheduler for CoQUIC. It keeps a durable
SQLite task queue, collects configured signals, runs Codex in task-scoped
boundaries, validates work, and optionally integrates approved changes into
`main`.

## Docker Compose operation

The trusted daemon is deployed as one Docker Compose service. It runs as the
configured numeric host UID/GID plus the Docker socket group and creates task
and scheduler-planner siblings through the standard local Unix Docker socket.
The daemon-owned clone is always `$COQUIC_HOME/repository/`; an interactive
checkout is rejected. Codex, GitHub, and cloud-publication credentials are
individual read-only files exposed only to the trusted service as
`/run/secrets/` targets. No task container receives the socket, whole home,
credentials, or daemon configuration. See
[CONTAINER_OPERATIONS.md](CONTAINER_OPERATIONS.md) for the durable contract.

Use the checked-in wrapper for bootstrap and lifecycle; it never calls
`docker compose down` or a global Docker prune:

```bash
bash steward/containers/manage.sh bootstrap
bash steward/containers/manage.sh start
bash steward/containers/manage.sh status
```

Bootstrap builds the pinned Nix `steward-daemon-image`, `steward-task-image`,
and no-Codex `steward-validation-image`, records exact local image IDs, validates the private
layout and credentials, and clones only an absent canonical repository. It
does not create credentials, initialize SQLite/epochs, or start work. Upgrades
require proven quiescence unless the operator explicitly
uses `--force`; ordinary stop preserves recoverable state.

## Quick start

Steward reads `$COQUIC_HOME/steward.toml` (`~/.coquic` by default).

```bash
export COQUIC_HOME="${COQUIC_HOME:-$HOME/.coquic}"
install -d -m 700 "$COQUIC_HOME"
cp steward/steward.example.toml "$COQUIC_HOME/steward.toml"
chmod 600 "$COQUIC_HOME/steward.toml"
uv run --project steward coquic-steward diagnostics
uv run --project steward coquic-steward daemon
```

Use `daemon --once` for one cycle. `tick` only records a durable wakeup; the
daemon consumes it. `status`, `timeline`, `audit-invariants`, and `diagnostics`
are read-only inspection commands.

```bash
uv run --project steward coquic-steward status
uv run --project steward coquic-steward tick --no-dispatch
uv run --project steward coquic-steward daemon --once
uv run --project steward coquic-steward diagnostics
```

The daemon performs local preflight, verifies the shared post-2.0 archive epoch,
reconciles durable task identities, repairs control-loop archive lag, and only
then dispatches work. A visible archive conflict sets `planning_blocked` while
queued and active task pipelines remain runnable.

## Control-loop archive

The scheduler archive is private local evidence under
`$COQUIC_HOME/control-loop/`:

```text
control-loop/
  epoch.json
  current.json
  events/YYYY/MM/DD.jsonl
  planner-runs/<planner-run-id>/
```

SQLite is the private operational source of truth. Fetches, repeated
observations, canonical signals, wakeups, cycles, planner dispositions, and
causal graph edges are committed there with monotonic event sequences. A
daemon-owned asynchronous writer materializes only ledger-confirmed event
bytes. Event files are append-only; startup may discard only an unconfirmed
incomplete final line. Raw scheduler records stay private local evidence.

Terminal planner runs are copied to a hidden same-filesystem stage, checked by
manifest descriptors, and atomically placed. The manifest covers every raw
prompt, transcript, result, activity, telemetry, and tool-change file that is
available. `current.json` is a bounded convenience projection and can be
replaced; local diagnostics reconstruct history from events and sealed runs.

See [CONTROL_LOOP_ARCHIVE.md](CONTROL_LOOP_ARCHIVE.md) for the storage and
recovery contract.

## Cloud publication

Steward keeps SQLite and local task/control-loop archives private. A completed,
inspected, sanitized generation is the only data sent to Cloudflare D1/R2; no
raw archive transport or transcript fallback runs beside it. See
[CLOUD_PUBLICATION.md](CLOUD_PUBLICATION.md) for eligibility, publication
order, recovery, and terminal archive cleanup.

## Planner boundary

The scheduler planner is one global Codex process per attempt. Every attempt
gets a fresh run ID, private session home, and process. Steward does not persist
a planner thread file, pass `--last`, or resume a provider session across
cycles. The planner sees current normalized signal IDs, active-task summaries,
the output schema, and read-only sealed prior run history.

The locked Docker bridge provides the outbound provider transport required by
`codex exec`. The planner has no host networking, network-administration
capability, repository, worktree, SQLite/WAL, Docker socket, daemon
configuration, or GitHub/SSH credential. Failed or invalid output seals a
failed run, leaves inputs pending, and uses bounded persistent backoff.
Accepted, duplicate, rejected, and capacity-skipped proposals remain ordinal
evidence.

## Task execution

Production task execution requires a locked task image digest and the
daemon-owned container boundary. A task container receives only its worktree,
task archive, Git metadata, bounded scratch, and one private session home.
Implementation is the only write-capable role. Validation uses scratch; planner,
reviewer, formality, and commit-message roles are read-only.

`CODEX_API_KEY` is delivered to the trusted wrapper as a length-prefixed stdin
value immediately before `execve`; it is not written to argv, labels, SQLite,
configuration, or archive records. The task image has no Docker socket,
GitHub/SSH credential, or daemon home.

Build and inspect the locked images with:

```bash
nix build --no-link .#steward-daemon-image .#steward-task-image .#steward-validation-image
bash steward/containers/smoke-test.sh --images
bash steward/containers/smoke-test.sh --isolation
```

See [containers/README.md](containers/README.md) for mount, identity, and
shutdown details.

## Signals and tasks

Signal providers are configured in `[steward.signals]`. A fetch records its
status even when a provider fails. Repeated observations remain evidence while
provider/fingerprint deduplication links them to one canonical signal. The
planner may consume a signal only when a verified task or an explicit no-work
decision covers it; invalid, rejected, capacity-skipped, failed, and
interrupted work leaves it pending.

Tasks are queued through the CLI or planner and are advanced by the daemon.
Use `enqueue`, `run`, `timeline`, and `status` for local operations. Commits,
pushes, issue comments, and external publication remain daemon or human
responsibilities; Codex workers do not perform those actions directly.

## State layout

```text
$COQUIC_HOME/
├── steward.sqlite          private task and control-loop ledger
├── tasks/                  raw task archive
├── control-loop/           raw scheduler archive
├── private/                session homes and bounded scratch
├── worktrees/              task worktrees
└── steward/                compatibility logs, prompts, and local diagnostics
```

Keep the entire state root private. Cloud publication reads a completed task
snapshot through the daemon boundary and writes only validated D1 metadata and
immutable R2 objects; it does not expose SQLite, raw archives, credentials,
worktrees, or session homes.

## Verification

```bash
nix develop -c uv run --project steward python -m pytest steward/tests -q
nix develop -c python scripts/validate_steward_cloud_contracts.py
nix develop -c pre-commit run --files steward/README.md steward/CLOUD_PUBLICATION.md
git diff --check
```

The daily suite skips the expensive `goodput` and `crosstraffic` benchmarks.
