# Steward container operations

This document is the canonical operations record for the Steward 2.0 host
deployment. Docker Compose is the only outer lifecycle manager. It runs one
trusted Steward service and the daemon creates task and scheduler-planner
containers as siblings through the standard local Unix Docker socket. Docker
outside Docker is accepted host authority for this trusted controller; it is
not task security. DinD, a nested daemon, systemd, rootless Docker, remote
Docker, a registry, and privileged mode are deferred decisions.

## Authority and paths

The service runs as the configured numeric host UID/GID and receives only the
numeric Docker socket group. `$COQUIC_HOME` is one absolute path identical on
the host, in the service, and in every task mount specification. The service
may read its whole home, but task/planner containers receive only their
allowlisted worktree, archive, session, scratch, Git, or sealed-history paths.
No task container receives the socket, repository clone, SQLite, deployment
state, daemon home, Compose files, or credentials.

The only canonical clone is `$COQUIC_HOME/repository/`. Bootstrap rejects a
dirty, detached, wrong-remote, wrong-branch, non-fast-forward, interactive, or
ambiguous clone. It never resets or repairs an existing checkout and never
uses the human interactive checkout.

Host credentials are individual private files below
`$COQUIC_HOME/private/credentials/`: the Codex API credential, GitHub
integration identity, and dataset-publication SSH identity. Known-hosts is
non-secret but is separately read-only. Compose exposes each file at its own
`/run/secrets/` target. Values never enter Compose YAML, `.env`, TOML, image
labels, container environment, Docker argv, SQLite, logs, or public archives.
The trusted daemon reads the Codex file only at a run boundary and delivers it
through the existing length-prefixed control pipe. It is never passed through
`docker exec --env`, `auth.json`, or a task-readable file.

## Releases and state

Images are built only from the pinned Nix outputs
`.#steward-daemon-image`, `.#steward-task-image`, and
`.#steward-validation-image`, loaded into the selected local daemon, and
inspected for exact IDs and immutable source, closure, architecture, protocol,
Codex, and runtime labels. The validation image is a one-shot no-Codex,
no-network boundary for the four canonical gates; it is never a Compose
service. The content-derived release identity is private deployment state.
The deployment directory contains:

```text
$COQUIC_HOME/private/deployment/
  current                 # atomic verified release selector
  previous                # immediately previous selector
  releases/<identity>.json # immutable image IDs and labels
  operation.lock
  operation.journal       # bounded phase and ownership facts
  last-outcome.json       # bounded status/category only
```

No selector changes until both images build, load, and inspect successfully.
The current and previous pairs, plus every image referenced by an active,
interrupted, recoverable, cleanup-pending, or nonterminal ledger record, are
retained. Reclamation can remove only exact Steward-owned unreferenced image
IDs. `docker system prune`, `docker image prune`, `docker container prune`,
age-based deletion, and removal of another Compose project's objects are never
used.

## Operations

`manage.sh bootstrap` takes the deployment lock, creates only the private
directory skeleton, validates ownership/mode of pre-existing credential files,
builds/verifies images, and clones the explicit remote only when the canonical
repository path is absent. It does not generate credentials, initialize the
database or archive epoch, contact the receiver, fetch signals, push, or start
normal processing. Repeating a successful bootstrap is idempotent.

`start` requires a completed bootstrap and delegates supervision to Compose
with `restart: unless-stopped`. Steward startup performs normal Plan 006
preflight, epoch initialization, reconciliation, and the Plan 009 two-root
sync. `stop` sends SIGTERM with a grace period strictly longer than Steward's
configured shutdown grace plus wrapper reconciliation allowance. It preserves
stopped task containers and recovery state and never calls `docker compose
down`.

`upgrade` builds a candidate and asks the bounded local health/quiescence API
whether task/planner runs, integration/push, archive writers, sync, or cleanup
are active. Busy or ambiguous state refuses before recreation. A forced
upgrade is visibly separate, invokes bounded Plan 006 shutdown, preserves
interruption evidence, recreates only the Steward service, and lets startup
reconciliation resume or fall back from exact identities. Failed health keeps
the candidate loaded but restores the previous verified selector. `rollback`
selects only a compatible recorded previous pair.

Every management phase is journaled before and after its side effect. Recovery
is deterministic: an interrupted layout/build/load/clone phase is retried only
when the journal proves exact operation ownership; a pre-existing repository is
never removed. An interrupted selector move compares both immutable records
before choosing current/previous. An interrupted Compose recreate leaves task
containers and archives untouched and startup decides recovery.

## Cleanup and pressure

Terminal cleanup belongs to the existing daemon transaction. After external
effects, archive writers, and the owning session quiesce, Steward seals and
verifies the terminal manifest, records `cleanup_pending`, removes the exact
stopped labeled container and bounded scratch, removes the disposable worktree
and eligible private session home, verifies the archive again, then records
`cleanup_complete`. A crash or Docker error leaves `cleanup_pending`; startup
and each bounded reconciliation retry only exact eligible ownership. Active,
interrupted, recoverable, unknown, mismatched, and foreign containers are
never removed by age.

Docker local-log rotation, writable layers, tmpfs scratch, process count, task
concurrency, and `$COQUIC_HOME` free space are measured as bounded facts.
Production must configure minimum home free bytes, higher free-space recovery
headroom, maximum Steward-owned Docker bytes, and a lower owned-byte recovery
threshold; there are no machine-independent production defaults. Under pressure,
eligible terminal cleanup and exact
unreferenced image reclamation run first. If usage remains high, Steward
persists/reports `resource_pressure`, stops admitting new planner/task work,
and continues heartbeat, active/recoverable work, archive writing, cleanup,
and synchronization. Admission resumes only above the free-space recovery
headroom and below the owned-byte recovery threshold.
Host-wide Docker usage is never claimed as Steward-owned and Docker's data root
is never mounted or scanned.

Local health/status reports only release identity, lifecycle/heartbeat, safe
task/container categories, cleanup-pending count, owned-byte and threshold
facts, sync health, and pressure state. It does not expose secret paths or
values, repository paths, raw inspect/config output, transcripts, inventory, or
raw exceptions.

Validation containers use the exact owner, epoch, release, runtime, and image
labels of their task or pipeline ledger row. They receive a read-only worktree
and a fresh bounded writable output/store only, with `--network none`, no
Docker socket, no host Nix store, and no credential mount. Gate command arrays
and exit identities are retained in private validation evidence before the
container and scratch root are removed. A crash leaves the exact resource
under `cleanup_pending` for startup reconciliation; unknown or mismatched
validation containers are reported and preserved.

## Operator rollout boundary

Real credential/key creation, receiver accounts and forced commands,
production `.env` values, remote permissions, live Compose bootstrap/start,
Site V2 coordination, an end-to-end canary, monitoring delivery, and a
rollback exercise are manual post-backlog operator work. This repository uses
fake credentials, local bare remotes, and temporary Docker state only. The
operator checklist is: provision individual files and ownership, verify the
canonical clone and pinned images, run `manage.sh bootstrap`, inspect bounded
`status`, start Compose, prove a complete signal-to-archive-to-Site V2 canary,
and exercise rollback without changing this contract.
