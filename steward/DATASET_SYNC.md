# Steward dataset synchronization

Steward's optional outbound publisher exposes exactly two public-by-placement
roots: `$COQUIC_HOME/tasks/` and `$COQUIC_HOME/control-loop/`. It never reads
the `$COQUIC_HOME` parent, private SQLite, credentials, worktrees, session
homes, a glob, a projection, a staging snapshot, an archive bundle, or a
generated aggregate.

## Transport contract

`StewardDatasetSynchronizer.run_once()` claims one dataset health row and starts
exactly one ordinary recursive rsync process. The argv contains the two
canonical directory paths without trailing slashes, then the fixed destination
`user@host::steward-dataset` over the locked SSH transport. Passing the
directories themselves preserves the stable sibling names at the forced
receiver root. The sender uses recursive visible regular
files and directories, timestamps, protected arguments, and
`--modify-window=-1`; hidden entries and special files are excluded by fixed
filters and by the absence of preservation flags.

The fixed SSH identity uses batch mode, strict host-key checking,
identities-only authentication, disabled agent, port, X11, local-command, and
PTY forwarding, and bounded connect/whole-transfer timeouts. The authorized
key is operator-installed and equivalent to:

```text
restrict,command="/usr/bin/rsync --server --daemon --config=/fixed/rsyncd.conf ." <public-key>
```

The receiver is rooted at one fixed dataset parent. Its parent, cache,
release, service, and SSH siblings are owned by another account/root. Only the
pre-created `tasks/` and `control-loop/` directories are writable. The fake
receiver harness checks those top-level names and rejects traversal, absolute
paths, hidden/special entries, deletion/source-removal, in-place, append,
partial, delayed-update, symlink, device, ownership, ACL, and xattr options.
The client destination cannot select a path or command. Real key generation,
installation, account/group ownership, and directory provisioning are
operator-owned actions; this repository contains placeholders and fake tests
only.

## Epochs and arrival order

Before every launch, both roots are revalidated as canonical non-symlink
directories with the exact basenames `tasks` and `control-loop`. Each
`epoch.json` is schema-valid and the two immutable `epochId` values are equal.
An invalid, mismatched, private, runtime, worktree, or symlinked source is a
bounded `source_invariant` health failure and does not rewrite an epoch or task
state.

Rsync has no cross-file or cross-root ordering. `epoch.json`, `current.json`,
daily event files, planner-run manifests, task metadata, and task manifests may
arrive before their related bytes. Site V2 must retain its last valid cache and
converge on a later cycle. Exit 24 caused by a live source race is explicitly
incomplete and retryable. Exit 0 means only that rsync completed; it does not
claim coherent publication, import success, or terminal-manifest validation.

The protocol deliberately keeps ordinary rsync temporary write/rename
behavior. It does not use delete/remove, in-place, append, partial, delayed
updates, batch mode, ownership/ACL/xattr/device/symlink transfer, remote shell
helpers, local copies, hashes, cursors, revisions, manifests, acknowledgements,
or per-file retries. Remote history is monotonic and has no retention policy.

## Lifecycle and health

The daemon reconciles an active dataset claim as `interrupted` at startup, runs
one immediate cycle, and schedules one non-overlapping monotonic 60-second
cadence. Missed ticks coalesce. Shutdown cancels the active process and may run
at most one bounded final cycle after task and control-loop writers are
quiescent; cancellation or deadline expiry remains an explicit incomplete
health outcome. Synchronization never blocks heartbeat, planning, task workers,
or archive writers.

Compose mounts the dataset publication identity as one trusted-service secret.
The dataset key and known-hosts material are absent from task/planner sibling
mounts and environments. A Compose upgrade is quiescent while a sync cycle or
archive writer is active; a forced upgrade preserves interrupted sync health
and lets normal daemon reconciliation retry it. Resource pressure may pause
new planner/task admission, but heartbeat, synchronization, writers, and
cleanup continue.

SQLite stores only one dataset health record: enabled state, active cycle ID,
last start/finish/success timestamps, duration, exit code, bounded category and
detail, and consecutive failure count. It stores no credential paths or
values, source fingerprints, cursors, revisions, manifests, remote inventory,
raw output, archive bytes, or importer acknowledgement. A concurrent claim
returns `busy` and starts no second process. The CLI exposes the same bounded
dataset-wide vocabulary.

Every-minute full-tree quick-check scanning is accepted initially and may
become scan-bound as history grows. Measure file count, scan time, bytes sent,
and overlap before proposing watcher journals, hashes, chunks, compression, or
dirty lists in a later protocol decision.
