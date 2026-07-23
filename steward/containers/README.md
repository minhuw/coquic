# Steward task containers

The daemon image is the trusted control side. It owns Docker, GitHub/SSH
integration credentials, SQLite, worktrees, public task archives, and the
transcript-sync key. The task image is an untrusted development closure and is
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
