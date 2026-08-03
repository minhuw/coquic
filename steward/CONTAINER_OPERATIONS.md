# Steward container operations

This is the canonical manual runbook for the Steward 2.0 host. Docker Compose
is the outer lifecycle manager. It starts one trusted daemon; the daemon starts
task, planner, and validation containers as siblings through the local Unix
Docker socket. Starting Steward is an operator action. Bootstrap never starts
the service, creates credentials, initializes SQLite, or contacts a receiver.

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
role gets one scoped writable worktree and scratch mount. Validation always
gets a read-only worktree plus bounded output and store mounts. The planner has
only sealed history, one private session, and output staging.

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

Use this sequence after the Cloudflare operator has verified D1 and installed
the three publication files. Keep non-secret Compose values in a private copy
of `steward/containers/.env.example`; it contains paths and limits, not
credential values. Before bootstrap or start, the daemon configuration must
also enable publication and point its credential fields at the daemon's secret
mounts.

1. Verify ownership and mode of the credential files, the absolute
   `COQUIC_HOME`, the canonical clone settings, pinned image inputs, and the
   local Docker Unix socket.
2. Create the host config at the absolute `STEWARD_CONFIG_PATH` from the
   private environment (the checked-in example uses
   `/srv/coquic-steward/private/runtime/steward.toml`) from
   `steward/steward.example.toml`. Compose mounts that file in the daemon at
   `/etc/coquic-steward/steward.toml`. Set every non-secret publication value
   explicitly; the account, database, buckets, R2 endpoint, public URL, and
   staging root are required before enabling the section:

   ```toml
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

5. Inspect bounded state before starting the service:

   ```sh
   bash steward/containers/manage.sh status
   ```

6. Start Compose explicitly and confirm the daemon health and release:

   ```sh
   bash steward/containers/manage.sh start
   bash steward/containers/manage.sh status
   ```

7. After Site is activated, run the read-only checker once for the empty state
   or for the first real published task. The checker is never a launch hook.

Bootstrap is idempotent. A successful repeat verifies the same clone and keeps
the current release; it does not initialize a database or begin processing.

## Lifecycle and recovery

The management wrapper is the only lifecycle interface:

```text
bash steward/containers/manage.sh config
bash steward/containers/manage.sh bootstrap
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
move compares immutable records before choosing `current` or `previous`.

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

## Site proof and delayed cleanup

An empty public D1 is healthy. Once Site is activated, run the retained checker
manually after the first real completed publication:

```sh
nix develop -c uv run --project steward python scripts/check-steward-deployment.py \
  --base-url https://coquic.minhuw.dev \
  --output .remote-ci/steward-deployment.json
```

The checker accepts the valid empty state with explicit skips. With a real task
it selects the first visible task, verifies ownership, loads the complete
trajectory, and proves one same-origin artifact action returns a safe `307`
redirect. Missing, malformed, private, integrity, ownership, and unsafe
redirect responses fail closed. Only transient endpoint failures are suitable
for a manual rerun. There is no scheduled monitor, synthetic canary, polling
loop, or fabricated task.

Site application deploy and rollback are owned by Site. They never alter D1,
R2, Pulumi state, Steward credentials, or the Steward release selectors. For
this rollout, the following exact set is the sole cleanup authority for retired
Site replica roots; it is a separate, delayed operator cleanup after the
checker proof and the chosen rollback window:

```text
/opt/coquic-demo/steward/tasks
/opt/coquic-demo/steward/control-loop
/opt/coquic-demo/steward/cache
```

Treat each listed directory as one exact target: remove at most one at a time
with an operator-owned command after verifying cutover. No other Site path or
document is cleanup authority for this rollout; do not add or reclassify a
target from another document. Ordinary Site deploy, repair, and rollback
remove none of these paths. Do not delete `$COQUIC_HOME/tasks`,
`$COQUIC_HOME/control-loop`, or any Steward source archive; those private
archives and their per-task verified cleanup protocol are not Site replicas.

## Local proof

The deterministic management tests use fake credentials, a local bare remote,
and fake Docker state only:

```sh
nix develop -c bash steward/containers/test-manage.sh --config
nix develop -c bash steward/containers/test-manage.sh --bootstrap
nix develop -c bash steward/containers/test-manage.sh --lifecycle
```

The production-shaped smoke entry point runs those checks plus planner-boundary
checks without launching a real service:

```sh
nix develop -c bash steward/containers/smoke-test.sh --production-compose
nix develop -c bash steward/containers/smoke-test.sh --planner
```

Image and Docker isolation checks are separate operator actions and require the
corresponding local tools. No local proof command performs a live Cloudflare,
Site SSH, or production lifecycle action.
