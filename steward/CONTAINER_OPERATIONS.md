# Steward container operations

This is the canonical manual runbook for the Steward 2.0 host. Docker Compose
is the outer lifecycle manager. It starts one trusted daemon; the daemon starts
task, planner, and validation containers as siblings through the local Unix
Docker socket. Starting Steward is an operator action. Production launch is
`bootstrap → init → start`; bootstrap never starts the service, creates
credentials, initializes SQLite, or contacts a receiver.

## Authority and private paths

Set one absolute `COQUIC_HOME` on the host and in the daemon. The only clone is
`$COQUIC_HOME/repository/`. Production remotes must be credential-free
`https://github.com/OWNER/REPO` URLs; SSH, other transports, userinfo,
query strings, fragments, and non-GitHub hosts are refused. Bootstrap refuses a
dirty, detached, wrong-remote, wrong-branch,
non-fast-forward, interactive, or ambiguous checkout and never resets an
existing clone or uses a human checkout. Local-path remotes are retained only
by `STEWARD_MANAGE_FAKE=1` test fixtures.

The trusted daemon is the only service with Docker authority and the full
private home. Compose mounts the local Unix socket and these host files as
individual read-only files:

| Host path | Compose target | Purpose |
| --- | --- | --- |
| `$STEWARD_CONFIG_PATH` (normally `$COQUIC_HOME/private/runtime/steward.toml`) | `/etc/coquic-steward/steward.toml` | private daemon config with inline GitHub token and CLIProxyAPI client key |
| `$COQUIC_HOME/private/credentials/d1-read-token` | `/run/secrets/d1-read-token` | Steward D1 publication token |
| `$COQUIC_HOME/private/credentials/r2-access-key-id` | `/run/secrets/r2-access-key-id` | public R2 access-key ID |
| `$COQUIC_HOME/private/credentials/r2-secret-access-key` | `/run/secrets/r2-secret-access-key` | public R2 secret access key |

The three publication files are produced by
`infra/cloudflare/scripts/deploy-production.sh`. All credential files are
regular, non-symlink files with mode `0600`, owned by `STEWARD_UID`; the
credential directory is mode `0700`. The daemon TOML and its backups are also
secrets: use regular non-symlink files owned by the daemon UID, mode `0600`
(`0400` is also accepted). `[steward.authentication].github_token` and `api_key` are inline in the same
private TOML; D1 and R2 credentials remain separate files. Secret values never
enter Compose YAML, `.env`, image labels, process arguments, SQLite, logs, or
public objects. Never print the private TOML or dump a real rendered Compose
configuration.

Task, planner, and validation containers receive only their declared worktree,
archive/history, session, scratch, Git, or output mounts. They receive no
socket, repository clone, SQLite, deployment state, daemon home, daemon
configuration, or secret-file mount.
Task roles get a read-only worktree view by default; only the implementation
role gets one scoped writable worktree and scratch mount. Validation always gets
a read-only worktree plus bounded output and store mounts. The planner has only
sealed history, one private session, and output staging.

The daemon runs as the configured numeric host UID/GID and receives the local
Docker socket group. Locked lifecycle operations provision private, daemon-owned
`private/runtime/daemon-passwd` and `daemon-group` files beneath `$COQUIC_HOME`,
bound read-only at `/etc/passwd` and `/etc/group` for OpenSSH numeric-UID lookup.
IDs must be canonical decimal integers in `1..4294967294`; the Docker group is
listed only once when it matches the primary group. Existing stopped deployments
receive these files on `init`/`start`; unchanged files retain their inodes, and
`config`, `status`, and live health reads never generate them. These mounts do
not apply to task or validation workers. Its container uses a read-only root with bounded `/tmp`
and `/run` tmpfs. Only container invocations use Codex's externally sandboxed
execution flag: Docker mounts, per-role UIDs/groups, dropped capabilities, and
resource limits provide isolation without nested user namespaces. Local Codex
invocations retain their configured sandbox. Validation runs with `--network none`
and excludes raw subprocess output. The raw subprocess output is never exposed
to validation.
For planner attempts, task roles, and same-session resumes, the wrapper delivers
`CODEX_API_KEY` from the daemon's private TOML as a length-prefixed value on stdin
immediately before `execve`. It never enters Docker/Compose environment metadata,
labels, argv, SQLite, transcripts, public artifacts, or worker config/auth files;
there is no Codex `auth.json` or redundant Codex credential file. The model
process receives the key in its environment; same-session process inspection
remains a known residual risk. Use a dedicated, revocable CLIProxyAPI client key.

## Releases and state

Build images from pinned Nix outputs and inspect their immutable IDs and labels. Every
release-producing management operation (`bootstrap`, `build`, and `upgrade`)
revalidates and builds only from `$COQUIC_HOME/repository/`; invoking the
management script from another checkout grants that checkout no production
source authority.

```text
nix build --no-link "$COQUIC_HOME/repository#steward-daemon-image" "$COQUIC_HOME/repository#steward-task-image" "$COQUIC_HOME/repository#steward-validation-image"
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

Set these exact, non-secret source-identity values in that private environment
before bootstrap:

```sh
COQUIC_REMOTE_URL=https://github.com/minhuw/coquic.git
STEWARD_EXPECTED_REMOTE=origin
STEWARD_EXPECTED_BRANCH=main
```

This is also the default remote when `COQUIC_REMOTE_URL` is unset. The HTTPS
URL contains no userinfo, password, or token. Host bootstrap and daemon Git/API
calls use `[steward.authentication].github_token` from the same private TOML
selected by `STEWARD_CONFIG_PATH`. There is no GitHub token-file fallback. Git
uses the native `gh auth git-credential` helper with that call's token in its
process environment, never in argv or persisted Git configuration. Do not run
`gh auth setup-git`, install host/global credential helpers, or embed tokens in
remote URLs. No Git SSH key or known-hosts file is required.

Use an expiring, repository-selected fine-grained PAT for `minhuw/coquic` with
Contents **read and write** for fetch/push. Grant API permissions only for
enabled features: Issues read/write for issue updates, Pull requests read/write
for PR workflows, and Actions read for workflow/run inspection (write only if
enabling workflow dispatch). Review the enabled workers against GitHub's API
permission requirements. Rotate the inline token before expiry, preserving
the TOML owner and private mode (including backups), then restart the daemon. GitHub App
installation tokens are a future option, not implemented provisioning.

Existing SSH deployments fail explicitly; operators must review and migrate
both the private environment/TOML (remove legacy SSH path fields) and the
checkout's fetch/push URLs to HTTPS. Management never rewrites private config or
an existing remote automatically. Remove any local URL rewrite/credential
configuration before preflight. The numeric-UID NSS identity mounts remain
required independently of the Git transport.

Fresh bootstrap runs Git in a clean configuration environment, so system,
global, and environment-injected URL rewrites cannot substitute the configured
canonical source. An existing `$COQUIC_HOME/repository/` checkout must use
`origin` at this exact URL and branch `main`; every fetch and push URL must
match the configured URL exactly. Any remote string mismatch is refused.

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
   `/etc/coquic-steward/steward.toml` as an individual read-only daemon-only
   mount. Set ownership to `STEWARD_UID` and mode `0600` before bootstrap; keep
   backups equally private (`0400` is accepted). The production override must
   include authentication, the runtime boundary, and every non-secret publication
   value (the authentication values below are fake):

   ```toml
   [steward]
   codex_bin = "codex"
   codex_sandbox = "workspace-write"
   runtime_protocol = "task-container-v1"
   validation_runtime = "validation-container-v1"
   local_codex_test_harness = false
   dry_run = false

   [steward.authentication]
   proxy_url = "https://proxy.example.test/v1"
   api_key = "fake-cliproxyapi-client-key-replace-me"
   github_token = "fake-github-token-replace-me"

   [steward.container]
   enabled = true
   image = "coquic-steward-task"
   repository_host_path = "/srv/coquic-steward/repository"
   state_host_path = "/srv/coquic-steward"
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

   The checked-in example is intentionally local-safe: authentication is
   commented out, container and deployment sections are disabled, and the test
   harness is enabled. Missing authentication is allowed for credential-free
   inspection and idle fixtures, but production preflight requires
   `github_token` plus both `proxy_url` and `api_key`. Copying the example without this production
   override is intentionally rejected when Compose supplies `STEWARD_RELEASE_ID`.

   The API key is a **CLIProxyAPI client key**, not the proxy management key,
   an upstream provider login, or a Codex login file. The URL and key apply to
   planner attempts, all task roles, and resumes. Use a proxy address reachable
   from the worker Docker bridge: host HTTP loopback (`127.0.0.1`) is not the
   container's loopback and will not reach a host-only listener. Prefer HTTPS;
   use HTTP only on a deliberately trusted, reachable bridge endpoint. Do not
   use host networking to bypass isolation. `dry_run = true` still consumes
   model API calls; it suppresses external task effects, not model usage.
   Restart the daemon after changing authentication or execution mode.

   Migration: remove `container.codex_api_key_path` and
   `deployment.codex_credential_path`; both are rejected with migration guidance.
   Remove the old `CODEX_API_KEY_PATH` deployment variable and Codex secret
   source/mount. Configure the inline authentication pair instead; no separate
   Codex credential file is required.

   GitHub migration: remove `deployment.github_token_path`, the old
   `GITHUB_TOKEN_PATH` deployment variable, and the GitHub secret source/mount.
   Set `[steward.authentication].github_token` in the same private TOML as the
   model proxy `api_key`; the GitHub token is independent of the model
   `proxy_url`/`api_key` pair. No file or ambient-login fallback is supported.
   Retire the old token file and protect any backups as secrets. Restart the
   daemon after changing the token (recreate the container if an atomic file
   replacement leaves its bind mount pointing at the old inode).

   Replace the example host prefix in `staging_root` when `COQUIC_HOME` is
   different, and create that real, non-symlink directory with mode `0700`
   before config validation. The credential paths in this override are
   daemon-container targets, not host paths; their host sources remain the
   individual D1/R2 files listed in the credential table. Keep cloud credential
   values out of TOML; GitHub and CLIProxyAPI credentials belong inline.
3. Load the non-secret environment in the operator shell and validate the
   production-shaped Compose file:

   ```sh
   bash steward/containers/manage.sh config
   ```

4. Run bootstrap. It validates config/credential file metadata without printing
   values, takes the deployment lock, creates the private directory
   skeleton, clones the configured remote only when the canonical clone is
   absent (reading inline GitHub authentication through the shared safe TOML
   parser), builds and verifies images, and records the first release:

   ```sh
   bash steward/containers/manage.sh bootstrap
   ```

5. Initialize the exact current Store while the daemon is stopped. The wrapper
   runs `coquic-steward init` in the selected daemon image with the production
   configuration, secrets, identity, and mounts. Repeating an exact init opens
   the Store without repairing or rewriting it; mismatches remain unchanged.
   The canonical Python loader validates TOML contents during init/start; shell
   `config` and bootstrap checks inspect only metadata, never parse secrets:

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

The management wrapper is the only lifecycle interface. Before constructing a
release, `bootstrap`, standalone `build`, and `upgrade` each validate the
canonical repository immediately before journaling or release mutation. The
script checkout remains authoritative only for management assets such as
`compose.yml`.

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
state; it never calls `docker compose down`. `status` reports the selected release
and Compose service state/health; resource and cleanup values are unknown there.
`logs` is limited to the Steward service.

Before launch, `start` runs `coquic-steward health --store-only`: exit 0 and
`{"mode":"store-only","store":"ok"}` mean the existing Store passes read-only
validation, not that a daemon is running. Neither health mode creates a missing
Store, migrates it, or resolves execution-mode admission latches. Keep the explicit
`bootstrap → init → start` sequence.

Compose and release verification use default `coquic-steward health`. Exit 0
requires a persisted running owner, a heartbeat no older than 90 seconds, and
matching runtime protocol and deployment release identity. Missing, stopped,
stale, or ambiguous daemon evidence fails closed. `release` comes from the daemon
claim, not the inspecting CLI's selected configuration. Resource pressure is
reported separately (`pressure`, `resourceObservedAt`) and does not make a live
daemon unhealthy; unobserved resource state is `unknown`.

`cycleProgress` reports only persisted current-start and last-completion times;
null means no recorded evidence. A fresh heartbeat does not prove scheduler or
publication progress. Publication and cleanup fields are bounded local ledger
facts, not remote-provider checks. Quiescence requires healthy runtime evidence,
an explicitly recorded idle cycle state and no observed task, planner, archive,
or cleanup work.

`upgrade` first probes the exact current daemon image for the runtime health
contract and verifies the running current release as a usable fallback. The probe
runs only the read-only `health` CLI in a disposable Compose container, never a
second daemon. Its `mode: runtime` and boolean `runtimeHealthy`/`releaseMatches`
fields establish API compatibility, not liveness; false values and exit 1 are
allowed for this capability probe only. Running-service verification remains
strict. The fallback check precedes build, journaling, stop, and recreation,
including with `--force`; force bypasses quiescence, not fallback safety.

Without `--force`, upgrade also proves quiescence through the daemon health API;
active task/planner work, integration, archive writing, or cleanup refuses the
operation. It then builds a candidate, recreates only the Steward
service, verifies the candidate release and heartbeat, and moves `current` and
`previous` atomically. A failed candidate is restored to the prior verified
release; the failed candidate remains recorded for diagnosis. `--force` is a
separate, visibly disruptive stop that preserves interruption evidence before
the recreate.

`rollback` probes both the recorded `previous` image and the current fallback
for the same contract, verifies the running current release, and requires proven
quiescence before journaling or recreation. A legacy target is refused without
stopping the current service or attempting a recreate/restore loop. It verifies
the started target's health before swapping selectors. If the previous pair
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

### Stopped legacy transition

Releases such as `3fedb2d6` report synthetic `heartbeat: ok` and `lifecycle:
running` from database readability and lack the new runtime health fields. They
are **not supported automatic upgrade fallbacks or rollback targets**. Neither
Docker's old healthcheck nor a successful legacy `health` command proves daemon
liveness. Do not add fields to release records, forge daemon evidence, or retry
with `--force`. Ordinary refusal leaves selectors, the operation journal, and the
service unchanged (apart from normal lock acquisition and disposable probes).
An already pending selector journal still goes through strict recovery first;
legacy or ambiguous runtime evidence leaves that journal untouched for review.
Restore also probes compatibility before journaling or recreating a fallback.

For an existing legacy installation, use this explicit maintenance-window
transition instead of `upgrade`. It deliberately gives up automatic rollback
across the health-contract boundary:

1. Retain the old immutable image IDs, release records, configuration, management
   assets, and a private backup location. Inspect any interrupted operation first;
   do not discard a pending journal to make a command pass. Arrange downtime and
   prevent concurrent operator or automated lifecycle commands.
2. Stop Steward with `manage.sh stop`. Verify the exact project/service container
   ID, image ID, and `coquic.steward.owner`, deployment, and release labels using
   Docker inspection, then verify `.State.Running` is false. If a pending selector
   journal prevents the wrapper from stopping, manually stop only that inspected
   container ID with `docker stop --time 45 <verified-container-id>` (use the
   configured grace). This is an explicit recovery exception to the wrapper-only
   interface, not liveness proof. Preserve interrupted task containers and resolve
   outstanding writers before taking a consistent offline backup of the private
   home, including SQLite/WAL, task state, and deployment metadata. Never prune or
   remove containers to force quiescence.
3. Update the canonical clean repository to the reviewed compatible revision on
   the configured branch. Keep the same home, credentials, and cloud identities.
   With the service confirmed stopped and the backup retained, retire only the
   old selector/journal pair under the existing lock. For example, after reviewing
   `operation.journal` and resolving its exact interrupted state:

   ```sh
   deployment="$COQUIC_HOME/private/deployment"
   (
     flock -n 9 || exit 1
     archive="$deployment/legacy-transition-$(date -u +%Y%m%dT%H%M%SZ)"
     mkdir -m 700 "$archive" || exit 1
     for name in current previous operation.journal last-outcome.json; do
       if [ -e "$deployment/$name" ]; then
         mv -- "$deployment/$name" "$archive/$name" || exit 1
       fi
     done
   ) 9>"$deployment/operation.lock"
   ```

   Do not move/replace the lock file, delete release records, or populate
   `previous` with the legacy release. If interrupted, inspect the archive and
   finish that exact retirement before bootstrap; do not start either release
   against a partial selector pair.
4. Using the new management assets, run `bootstrap → init → start`. Bootstrap
   now records the new first selector while preserving retained release records;
   `init` validates the existing exact Store, and `start` still uses Store-only
   readiness. A schema/configuration mismatch stops this procedure: restore the
   stopped backup or arrange a separately reviewed migration, never delete or
   rewrite the Store to bypass it. This health change performs no schema migration.
5. Before accepting the transition, inspect `status` and execute default health
   in that exact running container:

   ```sh
   docker exec --workdir "$COQUIC_HOME/repository" <verified-container-id> /usr/bin/env coquic-steward health
   ```

   Require exit 0,
   `runtimeHealthy: true`, `releaseMatches: true`, the expected release and
   protocol, and fresh persisted owner-bound heartbeat evidence. Start alone is
   not runtime verification. Subsequent compatible upgrades establish a new
   `previous` and support ordinary rollback.

If the first compatible launch fails, stop and inspect it; there is intentionally
no automatic legacy restore. To return to legacy operation, keep both daemons
stopped, assess any work/publication performed since the backup, and explicitly
restore the coherent stopped backup, old deployment selectors, and old management
assets before starting the retained old image. Never restore SQLite underneath a
running daemon or rewind state after external effects without reconciliation.
Legacy health still cannot certify runtime liveness; remaining on the old release
requires operator supervision, not a successful new-wrapper rollback claim.

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
and fake Docker state only. The lifecycle mode also exercises real health
parsers and journaling with mixed-version JSON: incompatible transitions preserve
selectors/journal/service, failed candidates restore compatible fallbacks, and
compatible upgrade/rollback remains supported.

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

Image, offline baseline, and Docker isolation checks require the pinned Nix
outputs and a local Docker daemon. CI runs the full baseline with networking
disabled, including flake evaluation, to catch missing locked source closures:

```sh
nix develop -c bash steward/containers/smoke-test.sh --images --full-validation
nix develop -c bash steward/containers/smoke-test.sh --isolation
nix develop -c bash steward/containers/smoke-test.sh --shutdown
nix develop -c bash steward/containers/production-canary.sh
```

For a focused task-image inspection-tool regression (no model or authentication),
build only `nix build --offline .#steward-task-image --no-link --print-out-paths`.
Before loading the returned archive, check free space on Docker's data filesystem
(`docker info --format '{{.DockerRootDir}}'` and `df -h`); retain existing images.
Load that exact archive with `docker load --input <archive>`, inspect its immutable
ID and source-revision/closure labels, then use that ID below. This deliberately
uses the image's default `PATH`, not a host tool mount or a task entrypoint:

```sh
docker run --rm --network none --entrypoint /bin/bash <immutable-task-image-id> -c '
  set -euo pipefail
  printf "PATH=%s\\n" "$PATH"
  command -v sed grep rg
  sed --version
  grep --version
  rg --version
  result=$(printf "skip\\nreviewer-tools-ok\\n" | sed -n "2p" | grep "^reviewer-" | rg "tools-ok$")
  test "$result" = reviewer-tools-ok
'
```

The canary exercises real production-identity provisioning, sessions, inline
authentication through the stdin wrapper, checkpoints, and rejection of a
deliberately failing candidate test. A fixed fake key and reserved proxy URL
are checked by the fake model executable without network calls; daemon config
and auth files stay outside task mounts. It never launches a live service or
contacts a provider.

These checks use fake inputs where possible and do not publish anything or
contact Cloudflare. No local proof command performs a live Cloudflare, Site
SSH, or production lifecycle action.
