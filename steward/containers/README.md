# Steward container boundaries

The daemon image is the trusted control side. It owns Docker, the GitHub
integration, SQLite, private worktrees and archives, and the cloud publication
client. The task image is an untrusted development closure. The validation
image is a separate no-provider, no-network closure for the canonical gates.
The planner image receives only sealed planning history, one private session,
and a bounded output directory.

## Mount and credential contract

Compose starts exactly one `steward` service from `compose.yml`. It runs as the
configured host UID/GID, receives only the local Unix Docker socket group, and
uses a read-only root with bounded `/tmp` and `/run` tmpfs. The daemon receives
the full `$COQUIC_HOME` plus these individual read-only credential files and a
known-hosts mount:

```text
/run/secrets/codex-api-key       <- private/credentials/codex-api
/run/secrets/github-identity     <- private/credentials/github
/run/secrets/d1-read-token        <- private/credentials/d1-read-token
/run/secrets/r2-access-key-id    <- private/credentials/r2-access-key-id
/run/secrets/r2-secret-access-key <- private/credentials/r2-secret-access-key
/etc/coquic-steward/known_hosts  <- private/credentials/known_hosts
```

The three publication files are installed by the Cloudflare rollout. Run that
rollout as the account configured by `STEWARD_UID`: bootstrap checks every
credential file as a mode-`0600` regular file owned by that UID, without reading
or printing its value. The credential directory is mode `0700`. No credential is
placed in an environment variable, image, label, Docker argument, SQLite row,
transcript, or public object.

Task containers receive only their task worktree, read-only archive, Git views,
bounded scratch, and one private session home. Read-only roles use the
read-only worktree view; only the implementation role receives one scoped
writable worktree and scratch mount. Planner containers receive read-only
sealed history, a fresh session, and output staging. Validation containers
receive a read-only worktree and bounded writable output/store with
`--network none`. None receives the Docker socket, daemon home, repository clone, SQLite,
deployment state, provider files, or raw subprocess output.

The task wrapper delivers `CODEX_API_KEY` as a length-prefixed value on stdin
immediately before `execve`; it is not persisted in `auth.json`, TOML, labels,
argv, or public artifacts. Same-session process inspection remains a known
residual risk; the credential is dedicated and revocable.

## Build and run commands

Build the pinned images without changing host state:

```sh
nix build --no-link .#steward-daemon-image .#steward-task-image .#steward-validation-image
```

The checked-in management wrapper is the only bootstrap and lifecycle command:

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

`config` validates the one-service Compose file and numeric limits; lifecycle
commands validate the configured local Unix socket. `bootstrap` validates
private files, creates only the daemon-owned
directory skeleton, clones the configured `main` remote only when the canonical
clone is absent, builds/releases the three images, and records an atomic
selector. It does not initialize SQLite, create credentials, contact a
receiver, or start normal processing. `start` is the explicit Compose launch;
`stop` preserves task state and never calls `docker compose down`.

`upgrade` requires proven quiescence unless `--force` is supplied, verifies a
candidate health/release identity, and restores the prior selector if health
fails. `rollback` selects only the recorded compatible previous pair and
restores the current pair if the rollback candidate fails health. Both retain
bounded journals and never change provider or Site state.

## Container smoke checks

Use fake inputs for local checks. The production-shaped mode runs management
configuration, bootstrap, lifecycle, and planner checks without starting a
real service:

```sh
nix develop -c bash steward/containers/smoke-test.sh --production-compose
nix develop -c bash steward/containers/smoke-test.sh --planner
```

Image inspection and Docker isolation are separate modes:

```sh
nix develop -c bash steward/containers/smoke-test.sh --images
nix develop -c bash steward/containers/smoke-test.sh --isolation
nix develop -c bash steward/containers/smoke-test.sh --shutdown
```

The image checks require the pinned Nix outputs. Isolation checks require a
local Docker daemon and prove that task and validation containers cannot reach
provider files, the host socket, or unrelated host paths. They do not publish
anything or contact Cloudflare.

## Pressure, cleanup, and Site handoff

Configure explicit host limits for free space, owned Docker bytes, process
count, memory, logs, and scratch. The daemon denies new work under pressure,
retains active/recoverable work, and reports bounded publication queue, blocked,
and cleanup facts. It never scans host-wide Docker state or runs broad prune
commands.

Terminal cleanup is tied to verified publication receipts and one exact archive
manifest. An interrupted or mismatched operation remains pending for daemon
reconciliation. Task, planner, and validation containers are never removed by
age or an unbounded glob.

Cloudflare rollout and Site configuration are separate operator actions. After
Site activation, an operator may run the read-only checker against an empty
deployment or the first real task; no container entrypoint runs it, and there
is no scheduled monitor or synthetic canary. Site deploy and rollback do not
alter the Steward release or cloud provider state. For this rollout, the
following exact set is the sole cleanup authority for delayed Site cleanup
after cutover proof and the rollback window:

```text
/opt/coquic-demo/steward/tasks
/opt/coquic-demo/steward/control-loop
/opt/coquic-demo/steward/cache
```

Those are Site-host replica roots. Treat each directory as one exact target and
remove at most one manually after the rollback window. No other Site path or
document is cleanup authority for this rollout; do not add or reclassify a
target from another document. Ordinary deploy, repair, and rollback remove
none. Do not delete Steward's private `$COQUIC_HOME/tasks`,
`$COQUIC_HOME/control-loop`, or source archives, and never replace the exact
paths above with a recursive glob.
