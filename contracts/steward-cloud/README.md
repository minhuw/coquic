# Harbor ATIF v1.7 schema

This directory contains the byte-stable JSON Schema generated from Harbor's
`Trajectory` model. It pins the immutable upstream base used by Steward and
Site contract work; CoQUIC-specific semantic restrictions are defined by later
contracts.

- Upstream: `https://github.com/laude-institute/harbor.git`
- Commit: `f742842cc914d99a081171c0ced3fe152715ac27`
- Schema version: `ATIF-v1.7`
- Model import: `harbor.models.trajectories.trajectory.Trajectory`
- SHA-256: `a597b620b77ecb4d0cff1b89fa6b74baf15086bea43fdb6c85d8b47df6cf3ec9`

The schema is serialized with `Trajectory.model_json_schema()`, JSON keys
sorted lexicographically, two-space indentation, UTF-8 encoding, and one
trailing newline. Harbor is not a CoQUIC runtime dependency.

## Reproduction

Run the following from the repository root. The `sed` stage removes the
development-shell banner so only the Python JSON output is captured.

```sh
harbor_dir=$(mktemp -d)
git -C "$harbor_dir" init
git -C "$harbor_dir" fetch --depth=1 https://github.com/laude-institute/harbor.git f742842cc914d99a081171c0ced3fe152715ac27
git -C "$harbor_dir" checkout --detach FETCH_HEAD
nix develop -c uv run --project "$harbor_dir" --frozen python -c 'import json; from harbor.models.trajectories.trajectory import Trajectory; print(json.dumps(Trajectory.model_json_schema(), indent=2, sort_keys=True))' | sed -n '/^{/,$p' > contracts/steward-cloud/atif-v1.7.schema.json
```

The resulting file must match the recorded SHA-256 and compare byte-for-byte
with this checked-in schema.

## CoQUIC ATIF semantics

Harbor owns the ATIF object shape: `agent`, `steps`, messages, multimodal
content parts, tool calls, observations, and the other fields in the pinned
schema. CoQUIC does not change those Harbor fields. The rules below are the
public transcript contract layered on top of that upstream structure.

- The root `schema_version` is exactly `ATIF-v1.7`. A public document is one
  complete, terminal run; it has no continuation reference and its
  `extra.coquic` object contains `taskId`, `pipelineId`, `runId`, `role`,
  `startedAt`, `completedAt`, `durationMs`, `disclosure`, and `artifacts`.
  IDs are non-empty logical IDs. Timestamps are timezone-aware RFC 3339
  values, completion is not before start, and duration is a finite number at
  least zero. Partial runs and raw JSONL are not ATIF publications.
- `steps` start at 1 and contain every integer exactly once in order. Tool
  calls have non-empty unique `tool_call_id` values within this trajectory.
  An observation `source_call_id`, when present, resolves only to a call in
  the same trajectory; it cannot point into a parent or embedded trajectory.
  Embedded subagent references resolve by `trajectory_id` only and every
  embedded trajectory has a unique ID. External trajectory paths are not
  public locators.
- Text content parts contain text. Image parts contain an
  `artifact:<artifactId>` logical reference and their media type is one of
  `image/jpeg`, `image/png`, `image/gif`, or `image/webp`. Other binary data is
  represented only by a logical descriptor in `extra.coquic.artifacts`, never
  by a path, URL, bucket, or object key.
- Each artifact descriptor has `artifactId`, `mediaType`, `sha256`,
  `byteSize`, and `ownerStepId`; IDs are unique, hashes are lower-case SHA-256
  values, sizes are non-negative integers, and the owner is an existing step.
  Every descriptor is referenced by its owning step's
  `extra.coquic.artifactIds` or by an image part owned by that step. Image
  descriptors use the supported image media types; non-image descriptors stay
  logical references and are never embedded as binary content.
- `extra.coquic.disclosure` has exactly two keys:
  `redactionApplied` and `originalRetained`. Both values are booleans. No
  private bucket name, object key, URL, credential path, token identifier, or
  private-shaped extension name/value may occur anywhere in a public document.
- Published bytes are UTF-8 JSON serialized with lexicographically sorted
  object keys, compact separators, and exactly one trailing newline. Duplicate
  object keys, alternate whitespace, missing/newline bytes, and non-UTF-8 input
  are rejected. The validator reports only rule names and JSON paths, never
  candidate secret values.

The executable definition is `scripts/validate_steward_cloud_contracts.py`.
Its `--atif-only` mode loads this pinned schema with
`Draft202012Validator`, then applies these cross-field checks to deterministic
in-memory clean, redacted, and malformed examples.

## D1 public metadata

`d1.sql` is a clean-launch, public-safe schema. It is intentionally not a copy
of Steward's private SQLite database and has no history migration or compatibility
read path. The seven concepts are `publication_generations`, `task_heads`,
`tasks`, `pipelines`, `runs`, `task_events`, and `artifacts`. Every generation
child has a `publication_id` foreign key. A task head is the only pointer used
by public reads; its `visible` state must join a `visible` generation. Staged,
superseded, hidden, dangling, or malformed rows are therefore absent from the
public query.

Publication follows one crash-resumable order:

1. Build and validate one complete terminal run and canonical metadata digest.
2. Upload and verify immutable public objects, then optionally upload and verify
   the private original.
3. Insert bounded, parameterized D1 batches and verify every expected row count.
4. In one transaction, supersede the prior generation, mark the new generation
   `visible`, and upsert the task head. A failure rolls back the whole swap.

The generation has a stable idempotency key, expected task/pipeline/run/event/
artifact counts, and a metadata digest. Retries reuse those values and converge;
conflicting metadata, counts, or digests fail closed; no partial generation is
exposed. Child rows are immutable after exposure.

## R2 keys and disclosure

Public objects use the exact content-addressed key grammar
`v1/tasks/<task-id>/objects/sha256/<first-two-hex>/<64-lower-hex-digest>`.
The first two characters must equal the digest prefix, and each row key must
embed that row's task and digest exactly. Logical artifact paths
remain in D1 and multiple paths or generations may reuse one public key. The
configured anonymous public R2 domain is the only public origin; D1 stores no
domain, URL, bucket, credential, or private locator.

An optional private original uses
`v1/originals/<task-id>/<run-id>/sha256/<64-lower-hex-digest>.jsonl`.
It is conditional and immutable, has no public or custom-domain URL, is never
written to D1 or ATIF, and expires after 2,592,000 seconds (provider deletion
may lag by about 24 hours). `redaction_applied` and `original_retained` are
bounded disclosure facts on artifact rows; they do not disclose the original.

Each statement and staging batch is bounded below 100 parameters and 100 KB.
`--d1-only` loads the schema with SQLite foreign keys enabled, exercises staged
isolation, atomic expose/supersede/repoint/hide, injected-swap rollback, row
counts, key and digest checks, object-key reuse, and private-locator denial.

## Staged publication payload

`publication.schema.json` is the producer-side Draft 2020-12 envelope. It is
staging input, not a public response: `generation.state` is always `staged`,
and `headIntent` records the desired task-head action without asserting that
any row is visible. The final D1 transaction verifies all rows and performs the
visible-generation/task-head swap atomically.

The envelope maps directly to the clean D1 tables:

- `generation` supplies `publication_generations`, including the stable
  publication/task/run identity, idempotency key, canonical `metadataDigest`,
  creation time, and expected task/pipeline/run/event/artifact counts.
- `headIntent` supplies the eventual `task_heads` identity and desired state;
  it is not exposed until the generation is verified.
- `task`, `pipelines`, `runs`, `events`, and `artifacts` supply the rows for
  `tasks`, `pipelines`, `runs`, `task_events`, and `artifacts` respectively.
  Every relationship is within the one publication and task, and every run is
  terminal and immutable. `runs.atifArtifactId` binds each run's ATIF digest to
  its public artifact.

Artifacts carry only logical relative paths, content-addressed public keys,
media types, sizes, lower-case digests, availability, and disclosure booleans.
Pipeline names are limited to 256 characters, run roles and event types to 128,
and logical paths are unique within one publication to satisfy the D1 columns.
When descriptors reuse one immutable public key, their digest and byte size must
also agree; exact content reuse remains allowed. The schema rejects unknown
fields and the validator rejects private locators, credentials, noncanonical
keys, dangling references, partial runs, count or digest mismatches, conflicting
artifact facts, and fabricated zero timestamps. A task may remain `active` when
its completed planning run is published; no incomplete run is represented.
