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
