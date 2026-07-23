# Raw task archive synchronizer

The standalone synchronizer copies the post-Steward-2.0 tree at
`$COQUIC_HOME/tasks/` directly to the fixed Site V2 receiver root.  The source
tree created by the task archive writer is authoritative: the synchronizer does
not reconstruct it from SQLite, parse task contents, or make a local
projection, revision tree, staging snapshot, manifest pass, cache, bundle, or
archive copy.  Durable, non-hidden files below `tasks/` are public by policy;
there is no filtering, redaction, secret scan, or approval step here.

## One operation

`TaskArchiveSynchronizer.run_once()` claims one health row and runs exactly one
ordinary recursive rsync operation.  It sends `tasks/` with a trailing slash to
`user@host::steward-tasks`, relying on the fixed daemon module to confine writes
to its receiver root.  The operation transfers visible directories and regular
files with timestamps, protected arguments, nanosecond quick-check support
(`--modify-window=-1`), and hidden-entry exclusions.  Symlinks and special
files are skipped by rsync because preservation flags are absent.  Rsync's ordinary
per-file temporary-write-and-rename behavior is retained; in-place, append,
partial, delayed-update, deletion, source-removal, symlink, device, socket,
FIFO, ownership, ACL, and xattr modes are forbidden.

The SSH command uses batch mode, strict host-key checking, identities-only
authentication, the dedicated identity and known-hosts files, no agent/port/X11
forwarding (`ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes`), no
PTY, and bounded connect and transfer timeouts.  The receiver
key is equivalent to:

```text
restrict,command="/usr/bin/rsync --server --daemon --config=/fixed/rsyncd.conf ." <public-key>
```

The fixed daemon config exposes exactly one write-only `steward-tasks` module
rooted at `/fixed/steward-tasks`, and refuses deletion/source-removal,
in-place, append, partial, delayed-update, link, device, special-file,
ownership, ACL, and xattr options. Refused options are space-separated as
required by rsync 3.2.7, including the short `D` device/special form. A fixed
`pre-xfer exec` check accepts only the exact `steward-tasks/` request exposed by
`RSYNC_REQUEST`, so a client cannot select a module subpath. This daemon-over-SSH
command is intentional:
stock `rrsync` rejects the protected-argument option required by the client.
The fake receiver harness starts the installed rsync daemon for protocol tests
and checks the exact forced command/module root; it does not emulate `--server`
arguments.  Real key generation, installation, rotation, receiver
configuration, and network provisioning are operator work.

## Consistency and health

The tree is eventually consistent.  Site V2 may observe files in a different
per-file order, including `manifest.json` before all content.  A live append or
replacement race can produce rsync exit 24; that is an incomplete, retryable
cycle, not successful publication and not a task failure.  Exit 0 is the only
success condition, and means only that rsync completed.  It does not mean Site
V2 imported or terminally verified every task.

The accepted initial tradeoff is a full-tree quick-check scan each minute (about
4,218 JSONL files and 1.94 GB of historical state at the measured baseline).
There are no watchers, dirty-task journals, fingerprints, per-file hash caches,
retention, deletion, or garbage collection.

SQLite stores only operational health: enabled state, active cycle ID, last
start/finish/success times, duration, exit code, stable failure category, a
short safe detail, and consecutive failure count.  It stores no archive bytes,
raw output, credential values or paths, remote inventory, revision, digest, or
task state.  Compare-and-set claim makes a second concurrent call return busy;
there is no internal retry, scheduling, task blocking, or remote-success
inference after interruption.  A restart can reconcile an active cycle as
`interrupted`.

Plan 006 owns loading user configuration, locking daemon-image SSH/rsync
versions, cadence, startup/shutdown/final cycles, CLI health, and proving the
sync identity is absent from task containers.  This module remains a transport
primitive until that lifecycle integration exists.
