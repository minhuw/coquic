# CoQUIC Steward

CoQUIC Steward is a local maintenance manager for CoQUIC. It keeps a durable
SQLite task queue, runs Codex workers in Steward-owned worktrees, captures
private execution artifacts, validates source diffs, asks an independent
reviewer to approve patches, and optionally integrates approved work into
`main`.

The operator interface is the Steward CLI. The daemon reads SQLite and CLI
wakeups, fetches configured signals, dispatches work, and publishes a sanitized
public mirror over outbound SSH. The public site reads that mirror; it is not a
control plane and never sends commands back to Steward.

## Quick Start

Steward reads global configuration from `$COQUIC_HOME/steward.toml`.
`COQUIC_HOME` defaults to `~/.coquic`. The repository-local example includes
the site-backed mirror settings:

```bash
export COQUIC_HOME="${COQUIC_HOME:-$HOME/.coquic}"
install -d -m 700 "$COQUIC_HOME"
cp steward/steward.example.toml "$COQUIC_HOME/steward.toml"
chmod 600 "$COQUIC_HOME/steward.toml"
```

Validate the copied configuration before starting the daemon:

```bash
uv run --project steward python -c \
  'from pathlib import Path; from coquic_steward.core.config import load_config; c = load_config(repo_root=Path.cwd()); print(c.public_mirror)'
```

The example keeps `public_mirror.publish = false` until SSH access has been
checked. Set it to `true` after completing the SSH checks below, then write a
local snapshot and inspect the task queue:

```bash
uv run --project steward coquic-steward publish-public-state
uv run --project steward coquic-steward status
```

Run the long-lived outbound-only scheduler:

```bash
uv run --project steward coquic-steward daemon
```

For a single deterministic cycle, use `daemon --once`. It consumes pending
CLI wakeups, performs configured signal work, dispatches according to the
requested options, and exits:

```bash
uv run --project steward coquic-steward daemon --once
```

The public dashboard is `https://coquic.minhuw.dev/steward`. Planner history is
at `https://coquic.minhuw.dev/steward/planner`. The dashboard is read-only;
use the CLI commands below to control Steward.

## Worker activities and evidence authority

Each code-stage worker run may produce a private `activities.jsonl` beside its
`codex.jsonl` transcript. A retry archives that sidecar as
`activities.retry-<n>.jsonl`; the final run owns the unsuffixed file. The
sidecar is mode `0600`, is never served directly, and is best-effort metadata.
During the retry delay, private transition state withholds the unsuffixed
sidecar until the next attempt finalizes its own evidence. The canonical
transcript remains byte-for-byte unchanged.

When a worker's internal intent changes, it may begin an agent message with one
standalone first line such as:

```text
STEWARD_ACTIVITY {"activity":"investigate","summary":"Trace closing-state packet generation"}
```

The closed activity vocabulary is `orient`, `investigate`, `edit`,
`self_validate`, `self_review`, and `report`. A declaration states current
agent intent only; it does not assert completion, success, validation, or
review. Steward supplies the schema version, sequence, receipt timestamp,
source event ID, stage, and `agent_declared` provenance. Invalid or missing
markers never change process outcomes, retries, lifecycle status, validation,
review, integration, or transcript bytes.

The public worker artifact exposes at most the 64 most recent declarations in
chronological order. Summaries are redacted and bounded to 240 UTF-8 bytes.
Availability is explicit: `available`, `not_declared`, `not_produced`,
`unavailable`, or `withheld` when transcripts are disabled. Planner and formal
reviewer artifacts have `activities: null` because this protocol describes
code-stage workers only.

| Evidence | Authority |
| --- | --- |
| Steward lifecycle phase | Canonical producer-observed task status; never inferred from worker output |
| Worker activity | Optional agent-declared intent; not a Steward gate |
| Command, file, and todo records | Codex-observed factual event types; purpose is not inferred |
| Command exit, validation, reviewer verdict, and patch | Outcome evidence |

Consumers should show the activity source and availability rather than
silently inferring a phase or outcome. In particular, `self_validate` is not a
Steward validation phase.

## Configuration

Only the global file `$COQUIC_HOME/steward.toml` is loaded. A file named
`steward.toml` in the repository is ignored unless it is passed explicitly to
`load_config()` by a tool or test. The complete example is
[`steward.example.toml`](steward.example.toml).

The main `[steward]` settings are:

- `codex_bin`, `codex_model`, `codex_reasoning_effort`, and `codex_sandbox`
  select the Codex executable and default run settings. The model is passed
  through without a Steward allowlist.
- `integration_mode = "local-only"` leaves an approved patch in Steward state.
  `"push-main"` queues integration work and can push the configured `main`
  branch when `local_only = false`.
- `git_remote`, `main_branch`, and `github_repository` identify the integration
  target and the repository used by signal providers.
- `scheduler_wait_interval_sec` controls how often the daemon checks SQLite for
  a CLI wakeup. Signal fetch intervals are configured per provider under
  `[steward.signals]`.
- `[steward.codex.<stage>]` can override model or reasoning independently for
  `signal_planner`, `implementation_plan`, `code`, `review`, and
  `commit_message`.
- `[steward.limits]` bounds active work and plan, worker, review, validation,
  and daily push operations.
- `[steward.path_policy]` lists repository-relative paths that worker patches
  may not change. Generated state such as `.remote-ci/` and `.rag/` should
  remain outside committed source.

### Model telemetry

Every Codex `exec --json` invocation writes a private mode-`0600` `telemetry.json`
sidecar beside its transcript. Transient retries are moved with their transcript
to `telemetry.retry-N.json`; the raw `codex.jsonl` bytes are never rewritten.
The sidecar records the configured model and reasoning effort, UTC start and
completion, monotonic duration, the first completed agent-message timing, every
valid `turn.completed.usage` record, exact input/cache/output/reasoning totals,
and bounded issue categories. A Codex turn is not an upstream request:
`model_requests`, TTFT, output streaming duration, and tokens per second are
explicitly unavailable with provenance `not_exposed_by_codex_exec`.

The optional `[steward.telemetry]` table accepts `billing_mode = "unknown"`,
`"chatgpt"`, or `"api"`, plus an operator-owned `price_catalog_path`. ChatGPT
and unknown billing never produce a cost. API cost is only an integer micro-USD
estimate when the configured model exactly matches one catalog entry covering
the invocation start time; cached input is a subset of input, reasoning is a
component of output, and the estimate is `uncached_input * input_rate +
cached_input * cached_rate + output * output_rate`, rounded with integer
arithmetic. Missing, stale, overlapping, malformed, or unmatched catalog data
leaves cost unavailable without affecting capture or task outcomes. The checked
in [`model-prices.example.json`](model-prices.example.json) catalog is
conspicuously fictional and non-operative.

Public run artifacts project bounded telemetry and retain totals when turns are
limited to 100. Task detail groups invocation counts by stage and run name,
counts only positive retry ordinals as retries, and reports legacy transcript
coverage separately. Full mirror writes also rebuild
`data/model-telemetry.json` (schema v1) by scanning all retained transcript
directories, independent of the 80-task display window. It reports all-time
coverage, oldest/newest evidence, and up to 400 ascending UTC days of completed
activity. Valid turns from partial captures remain in numeric totals while
missing or invalid sidecars, legacy transcripts, and in-flight runs keep
coverage incomplete; numeric totals never imply complete coverage.

### Public mirror

The `[steward.public_mirror]` section controls the sanitized v3 monitor
projection:

| Setting | Meaning |
| --- | --- |
| `enabled` | Generate the local mirror and publish runtime heartbeat/publication health. |
| `output_path` | Local mirror status-file path. A relative path is under `$COQUIC_HOME/steward`, not the repository checkout. The status file is accompanied by `data/tasks/`. |
| `publish` | When `true`, the long-lived daemon uploads changed snapshots over SSH. Keep it `false` until the preflight succeeds. |
| `transcript_mode` | Use `redacted` for the public site. `none` omits transcripts. `raw` is rejected when `publish = true` and must never be used for a public target. |
| `remote_user`, `remote_host`, `remote_port` | SSH destination for the site host. |
| `remote_path` | Absolute remote path to `status.json`; the publisher also syncs the adjacent `data/tasks/` directory. |
| `ssh_key_path` | Private key used for non-interactive SSH. The key must be readable only by its owner, normally mode `0600`. If omitted, `COQUIC_DEMO_REMOTE_SSH_KEY_PATH` is also accepted. |
| `known_hosts_path` | Known-hosts file used with strict host-key checking. Pre-seed the host key; do not disable host verification. |
| `connect_timeout_seconds` | SSH connection timeout. |
| `retry_initial_seconds`, `retry_max_seconds` | Exponential retry bounds after a failed publication. |

Code-stage worker artifacts may also contain an additive `change_trajectory`
projection. It is evidence of supported Codex tool-call behavior, not a
continuous monitor or a replacement for the executor-owned final patch. The
projection reports `available`, `not_produced`, or `unavailable` evidence and
keeps capture `complete`, `partial`, and `unavailable` completeness distinct;
publication never upgrades a private completeness state. Each worker exposes
at most the most recent 100 completed records, with at most 128 KiB of
redacted canonical Git delta per record and 512 KiB of patch text per worker.
Record counts and reconciliation counters remain visible when patch text is
truncated or omitted.

Trajectory records contain only a retry ordinal, bounded opaque tool-call ID,
supported tool name/status, sanitized relative paths, validated tree IDs, safe
error categories, and a recursively redacted Git delta. Private tool inputs,
responses, commands, prompts, context, session/turn IDs, raw exceptions,
credential material, filesystem paths, and URLs are never published. The
authoritative final attempt patch remains independent of this projection and
is the source of truth for the resulting change.

Planner and reviewer artifacts expose `change_trajectory: null`: capture is
enabled only for code-stage workers. Consumers should render trajectory
provenance and completeness explicitly and must not infer continuous
monitoring from its reconciliation fields.

### Hook-bound tool timing

Worker artifacts also expose an additive `tool_timing` object for the supported
`apply_patch` and `Bash` hooks. It is the elapsed interval between the valid
`PreToolUse` and matching `PostToolUse` receipts in Steward's synchronous hook
boundary. The source is always `codex_hook_boundary`. Durations use the private
manifest's `time.monotonic_ns()` arithmetic and are published as bounded,
non-negative `duration_ms` values. UTC start and completion timestamps are
correlation metadata only; they are never subtracted to calculate elapsed
time. The interval can include Codex dispatch and approval latency. It is not
child CPU time, shell-reported wall time, provider time, or network-only time.

| Evidence | Authority |
| --- | --- |
| Plan 001 trajectory | Supported tool intent and worktree transition |
| Plan 004 telemetry | Whole Codex invocation/model usage and duration |
| Plan 005 `tool_timing` | Steward-observed synchronous hook interval per supported tool |
| Final attempt patch | Authoritative initial-to-final worktree result |

Timing joins use the `retry_ordinal` plus opaque `tool_call_id` published on
both timing and trajectory records; IDs may repeat after a Codex resume.
Records are ordered by retry ordinal and hook start
sequence, with completion order retained only when it differs. The public
projection reports discovered, supported, completed, failed, incomplete,
unavailable, omitted, and published counts, a coverage state, and a
`truncated` flag. It publishes at most 4,096 records across retries and the
final invocation. A missing duration is unknown, never zero. Legacy runs
without hook evidence are `unavailable` with coverage `not_recorded`; Steward
does not backfill timing from host-local sessions, transcript mtimes, nearby
messages, or command output. Consumers should show the timing source and
coverage state explicitly.

`tool_timing` contains no command or response text, patches, prompts, paths,
private filenames, session or turn identifiers, raw exceptions, or credentials.
Failed and empty tools retain valid hook-bound durations, while unmatched,
invalid, unavailable, and omitted records remain incomplete rather than being
represented as zero. Planner and reviewer artifacts expose
`tool_timing: null`; model telemetry and `change_trajectory` remain independent
contracts.

For the checked-in deployment, the expected values are:

- SSH destination `minhuw@coquic.minhuw.dev:22`.
- Remote mirror path
  `/opt/coquic-demo/current/app/public/steward/status.json`.
- Public dashboard URL `https://coquic.minhuw.dev/steward`.
- Local key `~/.ssh/coquic-demo.key` and known-hosts file
  `~/.ssh/known_hosts`, unless the operator has an approved equivalent.

The remote account must be able to log in with the configured key in
`BatchMode`, run `bash`, `rsync`, and `flock`, and use non-interactive `sudo`
for the mirror destination. The publisher creates its private staging and lock
directories under `$HOME/.cache/coquic-steward`; it uses `sudo install`,
`sudo rsync`, and `sudo chmod` to update the site directory atomically. The
remote destination's parent must therefore be writable by the deployment
account through that sudo policy. The site only needs read access to the
resulting `public/steward/` tree.

### Deployed synthetic monitor

The deployed check is read-only. It fetches the dashboard, canonical v3 status
route, and one task detail when the status snapshot advertises a task. It
validates schema, JSON no-store/nosniff headers, freshness, latency,
task-detail shape, and the public redaction denylist. It never calls Steward,
changes publication state, or prints matched response values.

Run it locally against an explicitly selected target and keep the result as
sanitized evidence:

```bash
uv run --project steward python scripts/check-steward-deployment.py \
  --base-url https://coquic.minhuw.dev \
  --output /tmp/steward-monitor-result.json
```

The default thresholds are a 120-second maximum status age and a 2-second
maximum request latency. Use `--max-age-seconds` and `--max-latency-ms` for an
approved target-specific threshold; `--now` is reserved for deterministic
fixture checks. CI runs the check after deployment and every 15 minutes, then
uploads only the JSON result as an artifact.

Failure ownership is split by the first failed check:

| Check | Owner and first action |
| --- | --- |
| Dashboard route, status route, headers, or task route | Site/deployment owner: inspect the deployed build and route files, then roll back the site release if the route is unavailable or cached. |
| Schema or task-detail compatibility | Site and Steward release owners: deploy the compatible decoder first, then restore the producer snapshot or roll back the producer revision. |
| Freshness or publication evidence | Steward operator: inspect the daemon heartbeat and `publication` fields locally, then force a publication after fixing the outbound path. |
| Privacy or raw-transcript finding | Steward operator and security owner: disable public publishing, rotate exposed credentials if any, remove the affected public artifact, and redeploy the sanitized mirror. |
| Latency or network failure | Deployment/hosting owner: inspect the origin, proxy, and SSH publication path; do not retry by mutating daemon state. |

Rollback preserves local task execution. Set both `public_mirror.enabled = false`
and `public_mirror.publish = false` in the global configuration, restart the
daemon, and restore the last compatible site deployment through the normal
deployment process. Re-enable publication only after the synthetic check passes
against the canonical `/steward/status` route.

The daemon heartbeat is emitted every 30 seconds while it is running. The
site classifies a heartbeat up to 60 seconds old as live, up to 120 seconds as
delayed, and older data as stale. Publication retry state is included in the
mirror, so an SSH or site problem is visible without exposing local paths,
prompts, credentials, or raw private transcripts.

Before enabling publication, check the key, host key, remote tools, and sudo
policy explicitly:

```bash
mirror_key="$HOME/.ssh/coquic-demo.key"
mirror_hosts="$HOME/.ssh/known_hosts"
chmod 600 "$mirror_key"
ssh -i "$mirror_key" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$mirror_hosts" \
  -o ConnectTimeout=10 \
  minhuw@coquic.minhuw.dev \
  'command -v bash && command -v rsync && command -v flock && sudo -n true'
```

The command must finish without a password prompt. Run one forced publication
only after it succeeds:

```bash
uv run --project steward coquic-steward publish-public-state --publish
```

`--publish` deliberately overrides `publish = false` for that invocation and
uses the configured output path. Do not combine it with `--output`; use
`--output` for a local-only export.

## CLI Workflows

All commands below operate on the state selected by `$COQUIC_HOME`. Steward
control remains local to this CLI; the public dashboard only reads the mirror.

### Enqueue work

Add the built-in maintenance tasks:

```bash
uv run --project steward coquic-steward enqueue code-quality
uv run --project steward coquic-steward enqueue interop 1234567890
```

For other work, provide a title and either inline text or a prompt file. The
workflow controls whether implementation planning is run first:

```bash
uv run --project steward coquic-steward enqueue custom \
  "Investigate a failing test" \
  --prompt "Reproduce the failure, fix it, and run the focused tests." \
  --workflow fix

uv run --project steward coquic-steward enqueue custom \
  "Implement the requested feature" \
  --prompt-file /path/to/request.md \
  --workflow feature
```

`fix` runs code, validation, review, and integration. `feature` adds a
read-only implementation-planning pass before coding. A successful enqueue
prints the durable task ID used by the remaining commands.

### Wake and run the scheduler

`tick` records a durable scheduler wakeup; it does not require the daemon to
be holding the lock and does not execute a cycle in the CLI process:

```bash
uv run --project steward coquic-steward tick
uv run --project steward coquic-steward tick --no-plan --max-dispatch 1
```

The long-lived daemon consumes the wakeup. For a foreground one-shot cycle,
use:

```bash
uv run --project steward coquic-steward daemon --once --max-dispatch 1
```

Force a signal fetch by waking the daemon with all enabled providers or a
selected provider:

```bash
uv run --project steward coquic-steward fetch-signals
uv run --project steward coquic-steward fetch-signals --provider code-scanning
```

`plan` is the manual signal-to-task workflow. It prints proposed task specs;
add `--enqueue` to persist them:

```bash
uv run --project steward coquic-steward plan
uv run --project steward coquic-steward plan --enqueue
```

### Inspect and control tasks

List the most recent tasks, including their status and workflow:

```bash
uv run --project steward coquic-steward status --limit 50
```

Inspect the event timeline for a task ID returned by `enqueue` or `status`:

```bash
uv run --project steward coquic-steward timeline <task-id> --limit 200
```

Run one task directly when no daemon is running. `run` acquires the same
repository daemon lock as the scheduler, so it refuses to start while the
daemon owns the lock. A failed task returns a non-zero exit status; a blocked
task is reported as blocked without being treated as a CLI crash:

```bash
uv run --project steward coquic-steward run <task-id>
```

Audit SQLite invariants before investigating a task or publishing a snapshot:

```bash
uv run --project steward coquic-steward audit-invariants
```

### Write and publish monitor state

Write a sanitized local snapshot without SSH:

```bash
uv run --project steward coquic-steward publish-public-state
```

Write to a separate local path for inspection:

```bash
uv run --project steward coquic-steward publish-public-state \
  --output /tmp/coquic-steward-status.json
```

Force one SSH publication using `[steward.public_mirror]`:

```bash
uv run --project steward coquic-steward publish-public-state --publish
```

The daemon normally writes a new mirror after state changes and refreshes the
heartbeat while idle. A failed upload does not stop task execution; the daemon
records publication health and retries within the configured bounds.

## State and Artifacts

Generated state is stored under `$COQUIC_HOME/steward`:

```text
$COQUIC_HOME/steward/
├── steward.sqlite       durable tasks, events, signals, and wakeups
├── daemon.lock          advisory repository daemon lock
├── logs/                validation and daemon logs
├── prompts/             private Codex prompts and planner inputs
├── transcripts/         private Codex transcripts
├── patches/             private worker patches
├── implementation-plans/ persisted feature plans
└── public/steward/      local sanitized mirror and task detail files
```

Keep this state directory private. The public mirror is intentionally limited
and redacted, but local prompts and transcripts are not public artifacts.

### Codex change trajectories

Code-stage Codex runs may also contain a private `tool-changes/` directory
beside `codex.jsonl` and `last-message.md`:

```text
tool-changes/
├── manifest.jsonl       paired PreToolUse/PostToolUse behavior records
├── summary.json         bounded completeness and reconciliation evidence
├── patches/             canonical binary Git patches for tree transitions
└── .objects/            private Git objects used only for replay
```

The recorder is evidence-only. It snapshots the worktree at synchronous
`PreToolUse` and `PostToolUse` boundaries for the supported `Bash` and
`apply_patch` tools, matching records by Codex `tool_use_id`. It uses a private
temporary index and object directory and never stages the real index, changes
`HEAD`, or writes to the repository object database. A successful call with no
tree change is recorded as `empty`; the canonical Git patch, rather than a
shell command or `apply_patch` syntax, is the replay artifact.
Tool input and response payloads are size-checked at the hook boundary but are
not persisted; the manifest retains only metadata needed for pairing, timing,
and tree reconciliation.

Capture is complete only when the serial pre/post transitions replay to the
final captured tree without gaps, overlaps, unmatched hooks, or external
mutations. Missing or untrusted hooks, unsupported or specialized tools,
background writers, and recorder failures are reported as bounded
`partial`/`unavailable` evidence and never change Codex output, retry
classification, or task state. The final attempt patch remains authoritative
for the worktree result. Steward reconciles that patch after every executor
iteration save, so a late worktree write cannot leave an earlier `complete`
summary in place; reconciliation is idempotent.

Manifest updates use a private lock with a short bounded acquisition deadline.
Contention, snapshot, clock, parse, and write failures become allowlisted
diagnostic categories and the synchronous hook exits successfully. Private
files are mode `0600` under mode `0700` directories. No trajectory artifact is
copied to the public mirror.

Steward supplies these hooks as invocation-local Codex configuration only for
code-stage workers. It does not install project hooks under `.codex/` or edit
the operator's `~/.codex` configuration, so ordinary Codex sessions and
non-code Steward stages do not discover the recorder. Steward passes
`--dangerously-bypass-hook-trust` for its vetted hook command; if hooks are
disabled by operator or managed policy, the run still proceeds and its
diagnostics expose `unavailable`/`not_produced` trajectory evidence only.

Each transient Codex retry archives its complete trajectory as
`tool-changes.retry-<n>/` alongside the matching transcript and last-message
artifacts. A resumed process starts a fresh private capture context and
sequence space; the unsuffixed directory always belongs to the final attempt.

## Troubleshooting

### The site is stale or has no snapshot

Check both the public route and the local publication state. The route is
cache-safe and returns `503` with a reason when the file is missing, unreadable,
malformed, incompatible, or invalid:

```bash
curl -sS -H 'Cache-Control: no-cache' \
  https://coquic.minhuw.dev/steward/status
stat "$COQUIC_HOME/steward/public/steward/status.json"
uv run --project steward coquic-steward status
```

If local state is current but the site is old, request a scheduler heartbeat
and then force one publication:

```bash
uv run --project steward coquic-steward tick --no-plan --no-dispatch
uv run --project steward coquic-steward publish-public-state --publish
```

Inspect `runtime.heartbeat_at`, `publication.state`,
`publication.last_success_at`, and `publication.last_failure_category` in the
snapshot. If the local file is not changing, check that the daemon is running
and that `public_mirror.enabled = true`.

### The site reports a schema mismatch

The current public monitor contract is schema v3. Confirm the stored payload
and validate it against the checked-in schema:

```bash
uv run --project steward python -c \
  'import json; from pathlib import Path; from steward.schema.validate import validate_public_monitor; p = Path("steward/schema/fixtures/public-monitor-v3/idle.json"); validate_public_monitor(json.loads(p.read_text())); print("schema v3 ok")'
```

Do not hand-edit a production snapshot. Deploy a site build that understands
the producer schema, or keep the producer and site on the same migration
revision until both sides are compatible.

Schema changes start at `steward/schema/public-monitor-v3.json`. Additive
fields may remain on v3 because the producer and site tolerate unknown fields.
Removing or changing a required field requires a new schema version. Run
`uv run --project steward python steward/schema/generate_types.py` to refresh
the generated Python and TypeScript contract constants and types, then update
the compatibility fixtures and run the producer and site tests. Deploy the
site decoder before publishing a breaking producer version; rollback means
restoring the previous producer snapshot until the compatible site is live.

### Public data contains unexpected text

Use `transcript_mode = "redacted"` or `"none"`; never publish `raw`. Public
projection removes prompts, local paths, credentials, private metadata, and
unapproved transcript content. `raw` with `publish = true` is rejected during
configuration. After changing the mode, publish a fresh snapshot and inspect
the local `status.json` and task detail files before uploading. If a credential
has already been exposed, rotate it and remove the affected remote artifact
through the normal site deployment process.

### SSH publication fails

Read `publication.last_failure_category` first. The categories distinguish SSH
preparation, rsync transfer, timeout, permissions, serialization, and unknown
failures. Re-run the non-interactive preflight, including the exact key and
known-hosts file:

```bash
ssh -vv \
  -i "$HOME/.ssh/coquic-demo.key" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts" \
  -o ConnectTimeout=10 \
  minhuw@coquic.minhuw.dev true
```

Fix the key mode, host-key entry, remote `rsync`/`flock` installation, or
passwordless sudo policy as indicated. Then run
`publish-public-state --publish`; the daemon will also retry automatically
using `retry_initial_seconds` through `retry_max_seconds`.

### A direct run reports daemon lock ownership

`run <task-id>` and `daemon` share `$COQUIC_HOME/steward/daemon.lock`. Do not
run a task directly while the daemon is active. Check the owner and stop or
wait for the real daemon:

```bash
cat "$COQUIC_HOME/steward/daemon.lock"
pgrep -af 'coquic-steward (daemon|run)'
```

The lock is released when its owning process exits. Do not delete the lock
file to bypass an active owner; the lock is advisory through the file
descriptor, not the file's existence.

### The public site is unavailable

Steward task execution and SQLite state are local. A site outage or failed SSH
upload does not block enqueue, signal fetch, planning, validation, or direct
execution. Continue operating through `status`, `timeline`, `audit-invariants`,
and the local mirror. Once the site is healthy, run a forced publication and
confirm `publication.state = "published"`:

```bash
uv run --project steward coquic-steward audit-invariants
uv run --project steward coquic-steward publish-public-state --publish
```

If the daemon itself stopped, inspect its terminal/service logs and restart it
with `daemon`. A local UI is not required for recovery.

### Remote push preflight fails

With `integration_mode = "push-main"` and `local_only = false`, Steward checks
that local `main` matches the configured remote before starting the daemon. A
divergence error must be resolved by synchronizing and pushing `main` through
the repository's normal release process. Set `local_only = true` while
debugging a local workflow that must not mutate the remote.

## Outbound-only daemon

Steward has no inbound HTTP API. The daemon reads local SQLite and CLI wakeups,
then makes outbound signal, Git, Codex, and mirror connections. The public
Next.js site only reads the published files; it cannot enqueue tasks, wake the
scheduler, or execute work. Operator control remains the CLI surface
documented here.

## Task Workflows and Integration

Task kind describes the work domain, while workflow controls its execution
shape. New functionality normally uses `feature`; other work normally uses
`fix`.

Default `integration_mode = "local-only"` leaves a validated patch in the
Steward state directory and does not queue an integration task.

`integration_mode = "push-main"` queues integration after worker validation
and review. Integration rebases onto the configured main branch, re-runs
validation, and commits in a Steward-owned worktree. With `local_only = false`
it may push that commit to the configured remote main branch. Set
`local_only = true` while debugging; workers still do not commit or push.

Steward agents are internal worker definitions. `coquic-steward agents` lists
their worker names, mode, purpose, and embedded repository skills.
