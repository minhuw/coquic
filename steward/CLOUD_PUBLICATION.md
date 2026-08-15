# Steward cloud publication

Cloud publication is an optional, daemon-only boundary. SQLite and the local
task and control-loop archives remain private operational truth. Site V2 sees
only validated public metadata and precomputed usage projections in D1 plus
immutable sanitized objects in R2. The field-level payload, D1, R2, and ATIF rules live in
[contracts/steward-cloud](../contracts/steward-cloud/README.md); this document
describes the lifecycle and recovery boundary without repeating those tables.

## Eligibility

The session writes its transcript, activity, telemetry, result metadata, and
the publication snapshot locally. After a run leaves `running` and its archive
is fully materialized, the daemon composes one deterministic generation and
queues it in SQLite. The session thread never performs cloud I/O. A generation
is based on canonical task, pipeline, run, and content digests, not an attempt
counter or wall-clock identity. A completed planning run may publish while its
task remains active; a later completed run atomically supersedes that task's
visible head.

Running, partial, unstable, missing, or unsupported input is not publishable.
The builder converts the complete terminal run to the public ATIF form,
validates relationships and digests, scans text and source material, and
inspects supported images. Secrets, private locators, unsafe content, scanner
or OCR failures, and irreparable findings fail closed. Source or patch
findings can request a bounded revision, validation, and rescan before
integration; inspection output and matched values never enter public data.

### Staging boundary

Validated publication configuration supplies one private staging root to daemon,
CLI retry, session completion, integration composition, redaction, generation
string checks, and media metadata/OCR inspection. Each scanner creates a
mode-restricted descriptor-anchored child below that root, removes it on success
or failure, and never writes directly to the shared parent. Explicitly
unconfigured library and test calls retain their private temporary fallback;
the integration preflight source scan remains a separate source-safety boundary.

## Publication order

One generation follows this order. Each boundary is verified before the next
one begins, and provider calls occur outside local SQLite transactions.

1. Build and validate one complete terminal payload and its expected metadata
   row, object, idempotency, and digest counts. Steward derives immutable usage
   summaries, task-owned invocation/retry rows, bounded turns, price-entry
   provenance, and daily/lifetime global rows from sanitized ATIF evidence.
2. Upload each public object to R2 with its content-addressed key using a
   single-part conditional put, `Content-MD5`, and a follow-up `HeadObject`.
   A matching existing object is a successful replay; a conflicting object or
   descriptor is an integrity failure. SQLite records a receipt only after the
   descriptor is verified.
3. When sanitization changed the transcript and the original is available,
   conditionally upload the private original and verify its receipt the same
   way. It is never referenced by D1, ATIF, a public URL, or a public locator;
   provider expiry follows the cloud contract.
4. Before any hide request crosses the provider boundary, commit the task's
   local hide fence. The fence retires every pre-exposure generation and
   remains pending until the remote receipt is verified; SQLite is never held
   across the provider call.
5. Stage the D1 envelope in bounded, parameterized batches. D1 verifies the
   metadata and usage generation identities, foreign-key relationships,
   expected counts, canonical digests, six Token totals, nullable cost states,
   coverage, turn cursor order, exact rollups, and price provenance. Staged data
   has no visible task or usage head.
6. Expose only after staging succeeds and a mandatory local lease renewal still
   observes no hide fence. D1 atomically supersedes the previous visible
   metadata and usage generations, marks both new generations `visible`, and
   upserts the task and usage heads in one transaction. The client verifies both
   heads. Child rows and object bytes are immutable after exposure.

Aggregate overhead reconciliation is a separate D1-only path. It accepts only
the strict public allowlist from `StewardOverheadUsage.public_dict()`, stages a
detached generation with null task/publication identity and one global, and
updates the matching UTC-daily and model lifetime heads together. The lifetime
row replaces the prior daily contribution with safe-integer deltas; it never
allocates a synthetic task or detail identity. The producer and D1 compute the
same canonical digest, so a reused digest with different content fails before
any head changes. A stale compare-and-set or provider failure leaves both old
heads visible for retry.

## Durable recovery

The SQLite publication outbox is the durable operation record. It stores the
deterministic generation identity, bounded counts and digests, lease state,
verified public/private receipts, retry timing, and a safe failure category.
Workers reconcile pending local hide fences before claiming any exposure work,
then claim one generation with a bounded lease and renew it around each remote
operation. Restart reconciliation reclaims expired leases and resumes from
receipts; retries reuse the same identity and never overwrite an R2 object or
expose a partial D1 generation. The overhead cursor is advanced only after a
typed CAS/transport success, so a failed one-unit reconciliation remains the
next retry obligation. Network, quota, timeout, and other transient provider
failures leave the hide fence pending for the next worker cycle.
Conflicting identity, digest, count, schema, permission, or other permanent
failures stop publication and retain local evidence.

### Retry policy

`[steward.publication].max_retries` is an immutable runtime policy for one
publication worker or CLI operation. It defaults to `3` and accepts values from
`0` through `20`. The value counts retries after the initial claim, so `N`
permits at most `N + 1` normal claims/provider attempts. Retry backoff is a
separate timing setting and does not change that budget.

The outbox keeps `32` as the structural decoding bound for current-schema
rows. A later process may load rows written with a larger earlier policy and
apply a lower current policy without resetting their persisted attempts. Normal
rows at or above the current ceiling become blocked with `retry_exhausted`;
pending hide reconciliation remains claimable at that ceiling so a safety hide
cannot be stranded.

The bounded local recovery surface is available without exposing provider
responses or private paths:

```bash
uv run --project steward coquic-steward publication status
uv run --project steward coquic-steward publication list --limit 20
uv run --project steward coquic-steward publication retry <publication-id>
uv run --project steward coquic-steward publication hide <task-id> --reason operator_blocked
```

`status` reports queue, blocked, cleanup, age, and category facts. `list`
reports bounded metadata/usage generation summaries. `retry` rescans current
local evidence and enqueues only a changed deterministic generation. `hide`
commits the local fence, requests an atomic D1 metadata-and-usage head hide
that also supersedes every currently staged generation, verifies both hidden
receipts, and confirms the fence; it does not delete evidence. A pending hide
is always serviced before a queued generation can be claimed, including after
restart.

## Failure and hiding

Unsupported or unsafe content, scanner/OCR failure, irreparable findings, and
other disclosure failures commit a local hide fence before hiding any existing
public task head. Invalid identity, count, or schema state blocks without
exposing a new generation. A transient provider failure leaves the fence
pending; restart reconciliation retries it before any queued exposure work. D1
hide atomically hides the current head and supersedes all staged generations,
so a stage that races after hide cannot be exposed. A successful no-op hide is
still proof that no visible head remains. Blocked generations and their local
archives are evidence, never eviction targets. There is no raw transcript
fallback, partial publication,
global control-loop publication, scheduled live monitor, or dedicated canary.

## Terminal archive cleanup

Publication does not make an archive disposable by itself. For a terminal task,
the daemon first authenticates the final exposed generation and verifies every
expected public object receipt plus any expected private-original receipt. It
then records one durable cleanup intent containing the task identity,
publication identity, manifest digest, and one exact task-archive target.

On each attempt, the archive boundary re-verifies the manifest, proves the
target is the exact task child contained below the configured tasks root, and
performs the deletion with parent-directory durability where supported. The
intent is marked complete only after the deletion result is observed. A crash,
replacement, containment mismatch, missing receipt, or deletion error leaves
the intent pending or blocked for restart reconciliation; unpublished or
unverified evidence is never removed.

## Single-D1 bootstrap

The Cloudflare stack creates one protected current D1 with the complete
`contracts/steward-cloud/d1.sql` schema. Steward and Site receive the same
`d1_database_id`; there is no second database identity, compatibility reader,
private-object scan, or dual write. Provider output is captured under a private
temporary directory and reduced to value-free status messages.

The infrastructure operator first reviews a read-only structured Pulumi
preview, which retains the accepted plan privately, then reruns the command with
`--apply` to consume exactly that reviewed plan. Apply never creates a
replacement preview, and Pulumi rejects a plan that no longer matches provider
state or configuration. A blank D1 is initialized, an exact schema is reused,
and incompatible nonblank state fails closed. The successful bootstrap installs
the three protected Steward credential files and hands Site exactly four cloud
fields. A valid empty Site is accepted; real-task proof belongs to the on-demand
deployment checker.

A failed provider, schema check, credential install, or Site handoff stops before
the next boundary. Credential replacement is atomic and a Site handoff failure
leaves the installed Steward files available for a retry. Application rollback
restores the paired Site release/config and points Steward at the same
persistent D1 and configuration. Provider changes and token rotation remain
separately reviewed; no routine provider reversal runs.

## Deployment boundary

Publication is disabled by default in local fixtures. The trusted daemon alone
receives the D1 and R2 credential files; task, planner, and validation
containers receive none. Credential creation, Cloudflare bootstrap, Site
configuration, bootstrap, start, upgrades, and rollback belong to the
[container operations runbook](CONTAINER_OPERATIONS.md) and the infrastructure
runbooks. This document intentionally contains no credentials, host paths, or
live deployment commands. Historical raw archives remain private.
