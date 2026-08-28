# Steward container operations

This is the canonical manual runbook for the Steward 2.0 host. Docker Compose
is the outer lifecycle manager. It starts one trusted daemon; the daemon starts
task, planner, and validation containers as siblings through the local Unix
Docker socket. Starting Steward is an operator action. Production launch is
`bootstrap → init → start`; bootstrap never starts the service, creates
credentials, initializes SQLite, or contacts a receiver.

## Authority and private paths

Set one absolute `COQUIC_HOME` on the host and in the daemon. The only clone is
`$COQUIC_HOME/repository/`. Bootstrap refuses a dirty, detached, wrong-remote,
wrong-branch, non-fast-forward, interactive, or ambiguous checkout and never
resets an existing clone or uses a human checkout.

The trusted daemon is the only service with Docker authority and the full
private home. Compose mounts the local Unix socket and these host files as
individual read-only files:

| Host path | Compose target | Purpose |
| --- | --- | --- |
| `$COQUIC_HOME/private/credentials/codex-api` | `/run/secrets/codex-api-key` | provider credential delivered at a run boundary |
| `$COQUIC_HOME/private/credentials/github` | `/run/secrets/github-identity` | integration identity |
| `$COQUIC_HOME/private/credentials/d1-read-token` | `/run/secrets/d1-read-token` | Steward D1 publication token |
| `$COQUIC_HOME/private/credentials/r2-access-key-id` | `/run/secrets/r2-access-key-id` | public R2 access-key ID |
| `$COQUIC_HOME/private/credentials/r2-secret-access-key` | `/run/secrets/r2-secret-access-key` | public R2 secret access key |
| `$COQUIC_HOME/private/credentials/known_hosts` | `/etc/coquic-steward/known_hosts` | SSH host verification |

The three publication files are produced by
`infra/cloudflare/scripts/deploy-production.sh`. All credential files are
regular, non-symlink files with mode `0600`, owned by `STEWARD_UID`; the
credential directory is mode `0700`. Values never enter Compose YAML, `.env`,
TOML, image labels, process arguments, SQLite, logs, or public objects.

Task, planner, and validation containers receive only their declared worktree,
archive/history, session, scratch, Git, or output mounts. They receive no
socket, repository clone, SQLite, deployment state, daemon home, or secret.
Task roles get a read-only worktree view by default; only the implementation
role gets one scoped writable worktree and scratch mount. Validation always gets
a read-only worktree plus bounded output and store mounts. The planner has only
sealed history, one private session, and output staging.

The daemon runs as the configured numeric host UID/GID and receives the local
Docker socket group. Its container uses a read-only root with bounded `/tmp`
and `/run` tmpfs. Validation runs with `--network none` and excludes raw
subprocess output. The raw subprocess output is never exposed to validation.
The task wrapper delivers `CODEX_API_KEY` as a
length-prefixed value on stdin immediately before `execve`; it is not persisted
in `auth.json`, TOML, labels, argv, SQLite, transcripts, or public artifacts.
The same-session process inspection risk remains a known residual risk and
cannot be fully eliminated. The credential is dedicated and revocable for this
run.

## Releases and state

Build images from pinned Nix outputs and inspect their immutable IDs and labels:

```text
nix build --no-link .#steward-daemon-image .#steward-task-image .#steward-validation-image
```

The deployment directory is private and contains only bounded release facts:

```text
$COQUIC_HOME/private/deployment/
  current                 # atomic verified release selector
  previous                # immediately previous selector
  releases/<identity>.json # immutable image IDs and labels
  operation.lock
  operation.journal       # bounded phase and ownership facts
  last-outcome.json       # bounded status/category only
```

Selectors change only after all three images build, load, and pass inspection.
Current, previous, active, interrupted, recoverable, and cleanup-pending
release identities remain retained. Never run Docker-wide prune commands or
remove objects that are not proven Steward-owned and unreferenced.

## Ordered launch

Use this sequence after the Cloudflare operator has completed the direct
bootstrap and installed the three publication files. Keep non-secret Compose
values in a private copy of `steward/containers/.env.example`; it contains
paths and limits, not credential values. Before bootstrap or start, the daemon
configuration must enable publication and point its credential fields at the
daemon's secret mounts. Steward and Site use the same persistent D1 identity.

The Cloudflare operator reviews the read-only preview, which retains the
accepted plan privately, and then runs
`infra/cloudflare/scripts/deploy-production.sh --apply` to consume exactly that
reviewed plan. Apply never creates a replacement preview, and a plan that no
longer matches provider state or configuration is rejected. The command
initializes or verifies the exact current schema, installs the Steward files,
and hands Site its four cloud fields. A valid empty Site is accepted; real-task
checking is an on-demand operator proof. The bootstrap never fabricates a task
or applies an unreviewed provider change.

1. Verify ownership and mode of the credential files, the absolute
   `COQUIC_HOME`, the canonical clone settings, pinned image inputs, and the
   local Docker Unix socket.
2. Create the host config at the absolute `STEWARD_CONFIG_PATH` from the
   private environment (the checked-in example uses
   `/srv/coquic-steward/private/runtime/steward.toml`) from
   `steward/steward.example.toml`. Compose mounts that file in the daemon at
   `/etc/coquic-steward/steward.toml`. The production override must include
   the runtime boundary and every non-secret publication value:

   ```toml
   [steward]
   codex_bin = "codex"
   codex_sandbox = "workspace-write"
   runtime_protocol = "task-container-v1"
   validation_runtime = "validation-container-v1"
   local_codex_test_harness = false
   dry_run = false

   [steward.container]
   enabled = true
   image = "coquic-steward-task"
   repository_host_path = "/srv/coquic-steward/repository"
   state_host_path = "/srv/coquic-steward"
   codex_api_key_path = "/run/secrets/codex-api-key"
   docker_bin = "docker"
   network = "bridge"

   [steward.deployment]
   enabled = true
   home = "/srv/coquic-steward"
   repository = "/srv/coquic-steward/repository"
   docker_socket = "/var/run/docker.sock"
   host_uid = 1000
   host_gid = 1000
   docker_gid = 999
   expected_remote = "origin"
   expected_branch = "main"
   compose_project = "coquic-steward"
   codex_credential_path = "/run/secrets/codex-api-key"
   github_credential_path = "/run/secrets/github-identity"
   # Compose supplies release_id, daemon_image_id, task_image_id, and
   # validation_image_id from STEWARD_RELEASE_ID and the three immutable
   # STEWARD_*_IMAGE values; do not replace them with mutable image tags.
   stop_grace_seconds = 45
   max_pids = 512
   max_memory_bytes = 4294967296
   max_log_bytes = 67108864
   max_scratch_bytes = 8589934592
   min_free_bytes = 1073741824
   max_owned_docker_bytes = 4294967296
   recovery_free_bytes = 2147483648
   recovery_owned_docker_bytes = 3221225472

   [steward.publication]
   enabled = true
   account_id = "<cloudflare-account-id>"
   d1_database_id = "<d1-database-id>"
   d1_token_path = "/run/secrets/d1-read-token"
   r2_endpoint = "https://<cloudflare-account-id>.r2.cloudflarestorage.com"
   r2_access_key_id_path = "/run/secrets/r2-access-key-id"
   r2_secret_access_key_path = "/run/secrets/r2-secret-access-key"
   public_bucket = "<public-bucket-name>"
   private_bucket = "<private-bucket-name>"
   public_base_url = "https://<public-r2-host>/"
   staging_root = "/srv/coquic-steward/private/publication-staging"
   ```

   The checked-in example is intentionally local-safe: it disables the
   container and deployment sections and enables the test harness. Copying it
   without this production override is intentionally rejected when Compose
   supplies `STEWARD_RELEASE_ID`.

   Replace the example host prefix in `staging_root` when `COQUIC_HOME` is
   different, and create that real, non-symlink directory with mode `0700`
   before config validation. The three credential paths above are
   daemon-container targets, not host paths; their host sources remain the
   individual files listed in the credential table. Do not put any credential
   value in this TOML file.
3. Load the non-secret environment in the operator shell and validate the
   production-shaped Compose file:

   ```sh
   bash steward/containers/manage.sh config
   ```

4. Run bootstrap. It takes the deployment lock, validates every credential
   without reading or printing its value, creates the private directory
   skeleton, clones the configured remote only when the canonical clone is
   absent, builds and verifies images, and records the first release:

   ```sh
   bash steward/containers/manage.sh bootstrap
   ```

5. Initialize the exact current Store while the daemon is stopped. The wrapper
   runs `coquic-steward init` in the selected daemon image with the production
   configuration, secrets, identity, and mounts. Repeating an exact init opens
   the Store without repairing or rewriting it; mismatches remain unchanged:

   ```sh
   bash steward/containers/manage.sh init
   ```

6. Inspect bounded state before starting the service:

   ```sh
   bash steward/containers/manage.sh status
   ```

7. Start Compose explicitly and confirm the daemon health and release:

   ```sh
   bash steward/containers/manage.sh start
   bash steward/containers/manage.sh status
   ```

8. After the Site handoff, run the read-only checker once for the empty state
   or for the first real published task. The checker proves global and task
   usage surfaces, including run, invocation/retry, one bounded turn page,
   ownership, coverage, Token fields, and numeric/N.A. cost state. It is never
   a launch hook.

Bootstrap is idempotent. A successful repeat verifies the same clone and keeps
the current release; it does not initialize a database or begin processing.
Store initialization is a separate stopped-only transition; start validates the
exact Store and never invokes init.

## Lifecycle and recovery

The management wrapper is the only lifecycle interface:

```text
bash steward/containers/manage.sh config
bash steward/containers/manage.sh bootstrap
bash steward/containers/manage.sh init
bash steward/containers/manage.sh build
bash steward/containers/manage.sh start
bash steward/containers/manage.sh stop
bash steward/containers/manage.sh status
bash steward/containers/manage.sh logs
bash steward/containers/manage.sh upgrade [--force]
bash steward/containers/manage.sh rollback
```

`start` delegates to Compose with `restart: unless-stopped`. `stop` sends
SIGTERM with the configured grace and preserves task containers and recovery
state; it never calls `docker compose down`. `status` reports release,
lifecycle, bounded pressure and cleanup facts, and safe Compose health. `logs`
is limited to the Steward service.

`upgrade` first proves quiescence through the daemon health API. Without
`--force`, active task/planner work, integration, archive writing, or cleanup
refuses the operation. It then builds a candidate, recreates only the Steward
service, verifies the candidate release and heartbeat, and moves `current` and
`previous` atomically. A failed candidate is restored to the prior verified
release; the failed candidate remains recorded for diagnosis. `--force` is a
separate, visibly disruptive stop that preserves interruption evidence before
the recreate.

`rollback` requires a recorded compatible `previous` release and proven
quiescence. It verifies health before swapping selectors. If the previous pair
cannot start cleanly, the current pair is restored and the operation fails
closed. Neither upgrade nor rollback changes Pulumi, D1, R2, Site configuration,
or publication objects.

Every phase is journaled before and after its side effect. On restart,
reconciliation retries only an interrupted operation whose journal proves exact
ownership. A pre-existing repository is never deleted. An interrupted clone
temporary path is removed only when the journal names that exact path; unknown
or mismatched state remains for operator inspection. An interrupted selector
move uses a selector-pair journal written after health verification and before
the first selector write. It records the operation, the verified `fromRelease`
and `toRelease`, the pending selector, and the complete before/after pair. The
each temporary journal or selector file is fsynced before its atomic rename and
the deployment directory is fsynced after the rename. The pair is written in
this order:

```text
operation.journal: selector pending, selectorPending=previous
write previous
operation.journal: selector pending, selectorPending=current
write current
operation.journal: complete success
```

The next locked management command validates both immutable release records,
the selector values, and the running daemon identity before changing anything.
If the daemon is verified on `toRelease`, recovery finishes
`previous=fromRelease` and `current=toRelease`; if it is verified on
`fromRelease`, recovery restores the recorded before pair (including restoring
an absent `previous` selector). A recovery checkpoint with the exact before
pair and `selectorPending=current` is accepted only when the verified daemon is
still `fromRelease`; it resumes the restore idempotently. Any unknown release,
malformed or tampered journal, foreign selector, missing record, reserved
selector phase with a non-pending outcome, or running release outside the
recorded pair refuses the operation. Repeating recovery after either exact pair
is complete only revalidates it and marks the journal complete; it never guesses
a release or performs Docker cleanup.

## Pressure and cleanup

Configure these host-specific limits in the private environment:

```text
STEWARD_MIN_FREE_BYTES
STEWARD_RECOVERY_FREE_BYTES
STEWARD_MAX_OWNED_DOCKER_BYTES
STEWARD_RECOVERY_OWNED_DOCKER_BYTES
STEWARD_MAX_PIDS
STEWARD_MAX_MEMORY
STEWARD_MAX_LOG_BYTES
STEWARD_MAX_SCRATCH_BYTES
```

The daemon measures free space and exact Steward-owned Docker bytes. Under
pressure it records bounded pressure and publication queue/blocked/cleanup
counts, denies new planner/task admission, and continues active or recoverable
work, archive writing, and cleanup. Admission resumes only above the free-space
recovery headroom and below the owned-byte recovery threshold. Host-wide Docker
usage and Docker's data root are never claimed or scanned.

Terminal task cleanup remains a daemon transaction. After the remote generation
and every expected public/private receipt are verified, the daemon seals and
rechecks the manifest, records one exact `cleanup_pending` intent, and removes
only the stopped labeled container, bounded scratch, disposable worktree, and
eligible private session. A crash, mismatch, foreign object, or missing receipt
leaves the intent for restart reconciliation. Never use age-based deletion,
recursive globs, or a host-wide cleanup command.

## Site proof

An empty public D1 is healthy. Run the retained checker manually after the
bootstrap and, when available, after the first real completed publication:

```sh
nix develop -c uv run --project steward python scripts/check-steward-deployment.py \
  --base-url https://coquic.minhuw.dev \
  --output .remote-ci/steward-deployment.json
```

The checker accepts the valid empty state with explicit skips. With a real task
it selects the first visible task, verifies ownership, loads the complete
trajectory, proves one same-origin artifact action returns a safe `307` redirect,
and checks the metrics surfaces. Missing, malformed, private, integrity,
ownership, and unsafe redirect responses fail closed. Only transient endpoint
failures are suitable for a manual rerun. There is no scheduled monitor,
synthetic canary, polling loop, or fabricated task.

Site application deploy and rollback are owned by Site. They never alter D1,
R2, Pulumi state, Steward credentials, or the Steward release selectors. A
current-release rollback restores the Site pair and points Steward at the same
persistent D1 and cloud configuration. Provider changes remain a separate
operator action.

For the Cloudflare rollout, the following exact set is the sole cleanup
authority for delayed Site cleanup after cutover proof and the rollback window:

```text
/opt/coquic-demo/steward/tasks
/opt/coquic-demo/steward/control-loop
/opt/coquic-demo/steward/cache
```

These are Site-host replica roots. Treat each directory as one exact target and
remove at most one manually after the rollback window. No other Site path or
document is cleanup authority for this rollout; do not add or reclassify a
target from another document. Ordinary deploy, repair, and rollback remove
none. Do not delete Steward's private `$COQUIC_HOME/tasks`,
`$COQUIC_HOME/control-loop`, or source archives, and never replace the exact
paths above with a recursive glob. This cleanup set does not authorize
publication or a production lifecycle action.

## Local proof

The deterministic management tests use fake credentials, a local bare remote,
and fake Docker state only:

```sh
nix develop -c bash steward/containers/test-manage.sh --config
nix develop -c bash steward/containers/test-manage.sh --init
nix develop -c bash steward/containers/test-manage.sh --lifecycle
```

The production-shaped smoke entry point includes the focused Planner smoke internally, along with those checks, without launching a real service:

```sh
nix develop -c bash steward/containers/smoke-test.sh --production-compose
```

For focused Planner boundary verification, the standalone mode is optional:

```sh
nix develop -c bash steward/containers/smoke-test.sh --planner
```

Image and Docker isolation checks are separate operator actions. They require
the pinned Nix outputs, and isolation requires a local Docker daemon:

```sh
nix develop -c bash steward/containers/smoke-test.sh --images
nix develop -c bash steward/containers/smoke-test.sh --isolation
nix develop -c bash steward/containers/smoke-test.sh --shutdown
```

These checks use fake inputs where possible and do not publish anything or
contact Cloudflare. No local proof command performs a live Cloudflare, Site
SSH, or production lifecycle action.
