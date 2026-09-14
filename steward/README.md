# CoQUIC Steward

Steward is the local maintenance scheduler for CoQUIC. It keeps a durable
SQLite task queue, collects configured signals, runs Codex in task-scoped
boundaries, validates work, and optionally integrates approved changes into
`main`.

## Container operations

Production container operations, lifecycle, recovery, cleanup, Site handoff,
and local proof belong to the canonical [container operations runbook](CONTAINER_OPERATIONS.md).
This README is a product overview and navigation entry point; it does not
repeat the operational contract.

Production Git uses credential-free HTTPS (default
`https://github.com/minhuw/coquic.git`) and private inline `[steward.authentication].github_token` for
both Git and API calls. Use a repository-selected, expiring fine-grained PAT
with Contents read/write plus API permissions for enabled features; see the
[operations runbook](CONTAINER_OPERATIONS.md#ordered-launch). Tokens are never embedded in remote URLs or persisted in host/global Git config.
Legacy SSH remotes/configuration require an explicit operator migration.

## Quick start

Steward reads `$COQUIC_HOME/steward.toml` (`~/.coquic` by default). For local
(non-container) development and inspection:

```bash
export COQUIC_HOME="${COQUIC_HOME:-$HOME/.coquic}"
install -d -m 700 "$COQUIC_HOME"
cp steward/steward.example.toml "$COQUIC_HOME/steward.toml"
chmod 600 "$COQUIC_HOME/steward.toml"
uv run --project steward coquic-steward init
uv run --project steward coquic-steward diagnostics
uv run --project steward coquic-steward daemon
```

The example leaves `[steward.authentication]` commented out for credential-free
inspection and idle fixtures. Model execution uses an explicitly configured
`proxy_url` and inline `api_key` (a CLIProxyAPI **client** key, not its management
key or an upstream login). Keep this TOML and backups owned by the daemon UID,
regular/non-symlink and mode `0600` (`0400` also accepted). Never commit or print
them. Production requires the GitHub token and both model values; see the [private config and network
setup](CONTAINER_OPERATIONS.md#ordered-launch). They apply to planner, task, and
resume invocations, with no separate Codex credential/auth file. Restart the
daemon after changes, including GitHub token rotation. The GitHub token is
independent of the model `proxy_url`/`api_key` pair and lives in the same private
TOML. Remove legacy `deployment.github_token_path`, `GITHUB_TOKEN_PATH`, and
the GitHub secret source/mount; no token-file fallback is supported.

Migration: nonempty `codex_profile` and `COQUIC_STEWARD_CODEX_PROFILE` are no
longer supported. Steward's private Codex homes never import global profiles,
configuration, or saved logins. Remove those settings; use `steward.codex_model`,
`steward.codex_reasoning_effort`, or `[steward.codex.<stage>]` for model settings,
and `[steward.authentication]` `proxy_url`/`api_key` for authentication.

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
then admits work. `dry_run = true` is the fail-closed default. It is a
startup-only setting: changing it requires a restart, and legacy integration settings are rejected with migration guidance.

In dry-run mode, local planning, validation, commits, and archive materialization
may run, including model API calls that consume usage. External task effects
are suppressed and recorded as bounded proposals. Terminal tasks are sealed and verified locally, their private archives
are retained, and disposable containers, worktrees, and session homes are removed.
The aggregate result is `not-applicable`, `not-applied`, or `applied`; dry-run
success is rendered as validated with the external operation not applied. No
outbox row or Site V2/D1/R2 publication is created. Set `dry_run = false` only
when explicit live operation is intended.

A verified dry-run is never replayed automatically. After restarting Steward with
`dry_run = false`, use `coquic-steward rerun-live <dry-run-task-id>` to enqueue a
new live task. The command accepts only a successful (`succeeded` or `no_changes`)
dry-run task with finalized non-applied effect evidence and a retained, verified
archive. It revalidates every selected provider signal first; stale signals are
reported and omitted, while provider uncertainty or an all-stale selection is
rejected without mutation. A task with no genuinely linked signals may be
rerun. The source task, archive, proposal, patch, commit, and worktree remain
immutable; the daemon later executes the fresh task from current repository and
provider state. Repeating the command while its live descendant is active is
idempotent and does not create another task.

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
raw archive transport or transcript fallback runs beside it. An optional,
independent live-state worker POSTs only exact aggregate scheduler counts and
mode/planning state to the Durable Object gateway; heartbeat persistence never
performs network I/O. See
[CLOUD_PUBLICATION.md](CLOUD_PUBLICATION.md) for eligibility, publication
order, recovery, and terminal archive cleanup.

## Python dependency policy

`steward/uv.lock` is the sole authority for exact Python dependency versions in
both development and production. The Nix flake consumes that lock through the
uv2nix workspace; `flake.lock` pins uv2nix, pyproject.nix, and the build-system
inputs used to construct the environment. `steward/pyproject.toml` remains the
compatibility declaration and is not a second version authority.

Dependency updates require a reviewed change to the manifest and lock files,
followed by the complete CI suite. Builds and checks never update either lock
automatically.

## Planner boundary

The scheduler planner is one global Codex process per attempt. Every attempt
gets a fresh run ID, private session home, and process. Steward does not persist
a planner thread file, pass `--last`, or resume a provider session across
cycles. The planner sees current normalized signal IDs, active-task summaries,
the output schema, and read-only sealed prior run history.

The locked Docker bridge provides the outbound provider transport required by
`codex exec`. The planner has no host networking, network-administration
capability, repository, worktree, SQLite/WAL, Docker socket, daemon
configuration, or GitHub credential. Failed or invalid output seals a
failed run, leaves inputs pending, and uses bounded persistent backoff.
Accepted, duplicate, rejected, and capacity-skipped proposals remain ordinal
evidence.

## Task execution

Production task execution uses the locked task image and daemon-owned container
boundary described in the [container operations runbook](CONTAINER_OPERATIONS.md).
Task roles are isolated by worktree and credential boundaries; implementation
is the only write-capable role, while validation and planner roles remain
restricted.


## Signals and tasks

Signal providers are configured in `[steward.signals]`. A fetch records its
status even when a provider fails. Repeated observations remain evidence while
provider/fingerprint deduplication links them to one canonical signal. The
planner may consume a signal only when a verified task or an explicit no-work
decision covers it; invalid, rejected, capacity-skipped, failed, and
interrupted work leaves it pending.

Tasks are queued through the CLI or planner and are admitted by the daemon.
Each task receives a Store-owned monotonic execution latch. Dry-run tasks run
local work and retain proposal evidence; selected signals remain preview-covered
by their task and are not automatically replanned. Use
`enqueue`, `rerun-live`, `run`, `timeline`, and `status` for local operations.
`rerun-live` only enqueues; it never drives the daemon or reuses an old task's
execution artifacts. Commits, pushes,
issue comments, and external publication remain daemon or human
responsibilities; Codex workers do not perform those actions directly.

## State layout

```text
$COQUIC_HOME/
├── steward.sqlite          private task and control-loop ledger
├── tasks/                  raw task archive (including private effects.jsonl)
├── control-loop/           raw scheduler archive
├── private/                session homes and bounded scratch
├── worktrees/              task worktrees
└── steward/                current logs, prompts, and local diagnostics
```

Steward uses only this current layout. Historic roots and SQLite rows are never
scanned, imported, rewritten, or backfilled.

Keep the entire state root private. Only live tasks may cross the cloud
publication boundary. Dry-run archives and effect evidence remain local and
never reach Site V2, D1, or R2. Live publication reads a completed task snapshot
through the daemon boundary and writes only validated D1 metadata and immutable
R2 objects; it does not expose SQLite, raw archives, credentials, worktrees, or
session homes.

## Verification

```bash
nix develop -c uv run --project steward python -m pytest steward/tests -q
nix develop -c python scripts/validate_steward_cloud_contracts.py
git diff --check
```

`git diff --check` checks patch whitespace, not Markdown semantics. The configured
pre-commit hooks cover C/C++ and frontend files, not these Markdown documents.

The daily suite skips the expensive `goodput` and `crosstraffic` benchmarks.
