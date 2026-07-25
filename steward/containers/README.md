# Steward task containers

The daemon image is the trusted control side. It owns Docker, GitHub/SSH
integration credentials, SQLite, worktrees, public task/control-loop archives,
and the dedicated dataset-sync key. The task image is an untrusted development closure and is
created once per active task with only task-scoped mounts.

The daemon creates a task container with the locked `sha256` image digest,
read-only Git administration, a read-only archive, and separate worktree views.
The control protocol is `task-container-v1`.
Only an implementation session receives the task write group. Validation gets a
bounded scratch mount; planner, reviewer, formality, and commit-message roles
remain read-only. The trusted wrapper creates a private home for one persisted
session UID and then launches Codex as that UID.

`CODEX_API_KEY` is delivered as a length-prefixed control value on the wrapper
stdin immediately before `execve`. It is not persisted in `auth.json`, TOML,
SQLite, labels, Docker argv/configuration, or public artifacts. Codex tool
children use `shell_environment_policy.inherit = "none"` with the explicit
Steward allowlist.

The accepted residual risk is that a deliberately probing process in the same
session can recover its own key through `/proc` or an equivalent same-container
mechanism. The key is dedicated and revocable; rotation/revocation is the
response. This design does not claim same-session process isolation.

Build locked images with:

```text
nix build --no-link .#steward-daemon-image .#steward-task-image
```

Use `smoke-test.sh` with fake credentials and fake Codex output for image and
isolation checks. The Compose file is an example only and contains placeholders
for every host path and credential.

The daemon preflight resolves the locked task image and verifies host/container
path mappings before dispatch. The task image receives only its task worktree,
archive, scratch, Git metadata, and one private session home. It never receives
Docker, GitHub, SSH, dataset-sync identity, known-hosts, daemon home, or raw
subprocess output. Dataset credentials and receiver policy stay on the daemon.

Normal SIGINT/SIGTERM stops active task containers after the configured grace
(30 seconds by default) but preserves their state directories for restart.
Terminal cleanup removes a container only after a verified archive manifest and
durable `cleanup_pending`. Use fake values for smoke checks:

```bash
bash steward/containers/smoke-test.sh --shutdown
bash steward/containers/smoke-test.sh --dataset-sync
```

### Scheduler planner container

The scheduler planner is a separate daemon-owned boundary. Its locked image is
mounted with only:

* read-only sealed `$COQUIC_HOME/control-loop/planner-runs/` history;
* a fresh private session home for the one planner process; and
* a private output staging directory.

It uses `network=none` and has no repository, worktree, SQLite/WAL, Docker
socket, daemon configuration, GitHub/SSH/sync credential, or task image
authority. Every attempt receives a new planner run and session identity. A
planner failure is sealed and retried from the ledger; it does not resume a
provider thread or use `--last`.

The value-object boundary is `PlannerContainerConfig`; production runtime
construction must reject repository or credential mounts. The image and mount
contract can be exercised without network access by the planner smoke mode:

```bash
bash steward/containers/smoke-test.sh --planner
```
