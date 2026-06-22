# CoQUIC Steward

CoQUIC Steward is a small local maintenance manager for CoQUIC. It keeps a
durable task list, runs Codex workers in Steward-owned git worktrees, captures
transcripts, validates source diffs, asks an independent reviewer to approve the
patch, and optionally lets Steward push the validated patch to `main`.

Steward is intentionally simple: the daemon, CLI, Web UI, executor, task store,
and worktree manager all run in the local repository checkout.

## Quick Start

```bash
uv run --project steward coquic-steward enqueue code-quality
uv run --project steward coquic-steward status
uv run --project steward coquic-steward run <task-id>
```

Run one deterministic control-loop tick:

```bash
uv run --project steward coquic-steward daemon --once
```

Show the current signal-based plan:

```bash
uv run --project steward coquic-steward plan
```

Start the local API and Next.js Web UI:

```bash
uv run --project steward coquic-steward web
cd steward/web-ui
npm install
npm run dev
```

Then open `http://127.0.0.1:3000`. The FastAPI process listens on
`http://127.0.0.1:8765`; the Next.js dev server proxies `/api/*` to it. The
dashboard uses `/api/state` for snapshots and `/api/stream` for live updates.

## Configuration

Steward reads global config from `$COQUIC_HOME/steward.toml`, where
`COQUIC_HOME` defaults to `~/.coquic`. Repo-local config files are not loaded.

The example config is `steward/steward.example.toml`.

```toml
[steward.signals]
enabled = ["github-actions", "code-scanning", "codacy"]
```

## State

Generated Steward state is stored under `$COQUIC_HOME/steward`, where
`COQUIC_HOME` defaults to `~/.coquic`:

```text
~/.coquic/steward/repos/<repo-id>/
```

The task store is `steward.sqlite`. Transcripts, validation logs, prompts,
patches, and Steward-owned worktrees live under the same repo-specific state
directory.

## Steward Agents

Steward agents are internal worker definitions. They embed repo skill
`SKILL.md` files into the worker prompt when those skills are present.

| Steward worker | Embedded skills |
| --- | --- |
| `interop-doctor` | `debug-interop-run`, `quic-rag` |
| `code-quality-janitor` | `fix-code-quality-issues`, `quic-rag` |
| `ci-doctor` | `quic-rag` |
| `rfc-auditor` | `quic-rag` |
| `issue-implementer` | `gh-issue-implementation`, `quic-rag` |
| `work-item-creator` | `gh-work-item` |
| `reviewer` | `quic-rag` |

## Integration

Default `integration_mode` is `local-only`: Steward leaves a validated patch in
the repo-specific state directory under `$COQUIC_HOME/steward` and does not
queue an Integration task.

`integration_mode = "push-main"` makes Steward queue an Integration task after
a worker patch passes validation and review. Integration rebases the patch onto
the latest configured main branch, re-runs validation, and commits in a
Steward-owned worktree.

`local_only = false` is the default. With `push-main`, Steward may push to the
configured remote main branch after the Integration task passes validation.

Set `local_only = true` while debugging Steward behavior or new features. With
`push-main` and `local_only = true`, Integration stops after the local commit
and does not push or mutate GitHub. Workers are still instructed not to commit
or push; integration remains Steward-owned.
