# Steward cloud publication

Cloud publication is an optional, daemon-only boundary. SQLite and the local
task and control-loop archives remain private operational truth. Site V2 sees
only validated public metadata in D1 and immutable sanitized objects in R2.
The field-level payload, D1, R2, and ATIF rules live in
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

## Publication order

One generation follows this order. Each boundary is verified before the next
one begins, and provider calls occur outside local SQLite transactions.

1. Build and validate one complete terminal payload and its expected row,
   object, idempotency, and metadata-digest counts.
2. Upload each public object to R2 with its content-addressed key using a
   single-part conditional put, `Content-MD5`, and a follow-up `HeadObject`.
   A matching existing object is a successful replay; a conflicting object or
   descriptor is an integrity failure. SQLite records a receipt only after the
   descriptor is verified.
3. When sanitization changed the transcript and the original is available,
   conditionally upload the private original and verify its receipt the same
   way. It is never referenced by D1, ATIF, a public URL, or a public locator;
   provider expiry follows the cloud contract.
4. Stage the D1 envelope in bounded, parameterized batches. D1 verifies the
   generation identity, foreign-key relationships, expected counts, canonical
   metadata digest, and every staged row. Staged data has no visible task head.
5. Expose only after staging succeeds. D1 atomically supersedes the previous
   visible generation, marks the new generation `visible`, and upserts the
   task head. The client verifies both the visible generation and head. Child
   rows and object bytes are immutable after exposure.

## Durable recovery

The SQLite publication outbox is the durable operation record. It stores the
deterministic generation identity, bounded counts and digests, lease state,
verified public/private receipts, retry timing, and a safe failure category.
Workers claim one generation with a bounded lease and renew it around each
remote operation. Restart reconciliation reclaims expired leases and resumes
from receipts; retries reuse the same identity and never overwrite an R2 object
or expose a partial D1 generation. Network, quota, timeout, and other
transient provider failures use bounded retry. Conflicting identity, digest,
count, schema, permission, or other permanent failures stop publication and
retain local evidence.

The bounded local recovery surface is available without exposing provider
responses or private paths:

```bash
uv run --project steward coquic-steward publication status
uv run --project steward coquic-steward publication list --limit 20
uv run --project steward coquic-steward publication retry <publication-id>
uv run --project steward coquic-steward publication hide <task-id> --reason operator_blocked
```

`status` reports queue, blocked, cleanup, age, and category facts. `list`
reports bounded generation summaries. `retry` rescans current local evidence
and enqueues only a changed deterministic generation. `hide` requests a D1
head hide and reconciles the local record; it does not delete evidence.

## Failure and hiding

Unsupported or unsafe content, scanner/OCR failure, irreparable findings, and
other disclosure failures hide any existing public task head before the
generation is blocked. Invalid identity, count, or schema state blocks without
exposing a new generation. A transient failure leaves a retryable outbox state;
an interrupted hide is a durable obligation that is retried on the next
reconciliation. A successful no-op hide is still proof that no visible head
remains. Blocked generations and their local archives are evidence, never
eviction candidates. There is no raw transcript fallback, partial publication,
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

## Deployment boundary

Publication is disabled by default in local fixtures. The trusted daemon alone
receives the D1 and R2 credential files; task, planner, and validation
containers receive none. Credential creation, Cloudflare rollout, Site
configuration, bootstrap, start, upgrades, and rollback belong to the
[container operations runbook](CONTAINER_OPERATIONS.md) and the infrastructure
runbooks. This document intentionally contains no credentials, host paths, or
live deployment commands. Historical raw archives are not migrated.
