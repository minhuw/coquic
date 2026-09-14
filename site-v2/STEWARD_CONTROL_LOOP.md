# Steward Global Control-Loop Boundary

Site V2 consumes two independent public Steward sources. The Durable Object
live snapshot publishes aggregate control-loop state; visible D1 publications
and immutable R2 objects remain the archive for task history and detail. Site
never derives one source from the other or uses either as a fallback.

## Live snapshot boundary

For every server-rendered `/steward` request, Site performs one bounded,
no-store `GET` to `COQUIC_STEWARD_LIVE_SNAPSHOT_URL`. The response is the closed
`schemaVersion: "1.0"` object defined by
[`schemas/steward-live.schema.json`](schemas/steward-live.schema.json):

- `availability`: `live` or `stale`;
- strict UTC `observedAt` and `staleAfterSeconds` from 30 through 3600;
- public daemon mode: `production` or `dry-run`;
- pending Signals count;
- Planning state: `active`, `idle`, or `paused`;
- Tasks active and queued counts; and
- Integration active and queued counts.

Counts are nonnegative safe integers. The object and every nested object are
closed. Unsupported versions or states, unknown fields, invalid timestamps,
unsafe integers, timeout, non-JSON, non-success, and oversized responses make
live state explicitly unavailable. Stale values retain their exact count/state
with a stale label. Site adds no polling, browser fetch, WebSocket, retry loop,
or local cache.

The live snapshot intentionally carries no task IDs, titles, transcripts,
artifacts, events, or history. Only the declared daemon mode is public; all
other operator and daemon configuration remains private.

## Archive task boundary

Task events remain rows in the visible D1 publication for their owning task.
Site validates task ownership, expected event count, contiguous sequence,
relationships, and immutable R2 evidence before returning archive detail. A
completed planning run attached to a task is archive evidence, not the global
Planning state.

Archive status, active publications, history counts, task detail, usage,
trajectories, and artifacts retain their existing D1/R2 behavior. Live failure
must not suppress archive history. Archive failure must not change a valid live
snapshot. Site never infers live Signals, Planning, Tasks, or Integration values
from archive rows.

## Ownership

The separately deployed Worker/Durable Object owns live snapshot production and
availability. The Steward cloud publisher owns D1/R2 archive creation and
exposure. Site owns server-only acquisition, exact boundary validation, honest
state rendering, and deployment of the non-secret upstream URL. Site itself
deploys no Worker, database, sidecar, importer, or control-plane mutation.

Revision remains outside the live and archive contracts. Adding it requires a
current schema and producer field rather than inference from task events,
timestamps, labels, or payloads.
