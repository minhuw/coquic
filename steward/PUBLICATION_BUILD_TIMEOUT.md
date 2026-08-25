# Publication build-timeout retirement record

**Status:** accepted

**Decision:** immediate rejection with a zero-release deprecation window.

**Runtime effect:** The first changed release rejects retained
`build_timeout_seconds` keys through the existing strict unknown-key validation.
Key-free publication configuration remains compatible with the previous release;
publication, retry, cancellation, and failure behavior are otherwise unchanged.

## Compatibility transition

The first changed release rejects `build_timeout_seconds`; operators must remove
the key before upgrading. The immediately previous release accepts the same
key-free configuration, so rollback uses that configuration with the previous
release. There is no warning period, compatibility alias, automatic rewrite,
fleet migrator, or migration tool; no timer is implemented, and direct Python
construction with the removed dataclass keyword is unsupported.

## Evidence map

### Pre-retirement configuration surface

- Before retirement, `StewardPublicationConfig.build_timeout_seconds` was a
  frozen configuration field with a `300.0` default. Its constructor validated
  it as a finite, positive value no greater than `86400` seconds and stored the
  normalized value.
- Before retirement, `_publication_config` included `build_timeout_seconds` in
  its strict allowlist and supplied the same `300.0` default when loading TOML.
  Unknown keys were rejected rather than ignored.
- Before retirement, the example advertised `build_timeout_seconds = 300`. The
  example configuration test loaded the publication table successfully, while
  the configuration tests established that unsupported publication keys fail.
- The pre-retirement repository inventory found only parser/default/validation
  and example references. There was no read of the value by a publication
  caller, builder, provider client, retry policy, or test.
- History identifies `ee94b9fd feat(steward): configure cloud publication` as
  the introduction commit. That change added strict cloud publication settings
  and the example field, but did not establish deadline semantics or a
  consumer. Repository history cannot establish whether downstream operator
  configurations treated the accepted key as a supported promise.

### Composition callers

Publication composition is synchronous and is invoked through several paths:

| Caller | Evidence | Current behavior relevant to this packet |
|---|---|---|
| Session completion hook | `steward/src/coquic_steward/execution/session.py:271-308` | Composes a completed materialized run without provider I/O, queues a valid generation, and catches failures so the session result is unchanged. Daemon reconciliation can retry the same run later. The build timeout is not passed. |
| Daemon publication worker and reconciliation | `steward/src/coquic_steward/orchestration/daemon.py:973-1032,2944-2969` | Provider clients use `network_timeout_seconds`; lease and retry settings are applied separately. Credential-aware composition is repeated before provider I/O and during terminal receipt verification. The build timeout is not passed. |
| CLI hide/retry paths | `steward/src/coquic_steward/cli.py:145-209,337-380` | D1 hide uses the network timeout; retry rebuilds current local evidence with the configured credentials and staging root. The build timeout is not passed. |
| Cloud publisher/composer boundary | `steward/src/coquic_steward/publication/publisher.py:1-7,591-710,933-1010` | The publisher coordinates durable outbox work and composes through the canonical composer. It classifies provider/transient outcomes and schedules durable retries, but has no build deadline input. |

The caller map means a future deadline cannot be added safely to only one
entry point. It must define whether the same contract covers completion,
reconciliation, terminal verification, and CLI retry, and how a deadline is
represented when composition is repeated.

### Existing timeout owners

The current owners are narrower than an end-to-end publication build:

- `scanner_timeout` bounds scanner invocations in generation and media
  inspection; `ocr_timeout` bounds OCR work for image inspection
  (`steward/src/coquic_steward/publication/generation.py:1967-2086`,
  `steward/src/coquic_steward/publication/media.py:1187-1239,1307-1368`).
  These are stage/provider-specific inputs, not a total composition budget.
- `network_timeout_seconds` is passed to R2 and D1 clients by the daemon and
  D1 client construction in the CLI (`daemon.py:973-987`, `cli.py:179-201`).
  It covers provider requests, not local conversion or inspection.
- `lease_duration_seconds` governs the durable outbox claim lease, while
  `max_retries` and `retry_backoff_seconds` govern provider/outbox retry
  scheduling (`daemon.py:994-1005`; `publication/publisher.py:617-639,854-909`).
  Neither is a build deadline.
- Session execution has separate plan, review, and worker stage timeouts
  (`steward/src/coquic_steward/execution/session.py:2153-2161`). They belong to
  Codex task execution and must not be reinterpreted as publication build time.

### What a build currently does

`compose_publication_generation` detaches and freezes the source graph, then
runs the publication builder. The builder converts the completed run,
sanitizes it, scans strings and source material, inspects each retained
component, may invoke scanner and OCR child processes, creates a validated
public bundle, and returns a bounded generation or failure outcome
(`steward/src/coquic_steward/publication/generation.py:1967-2086`,
`steward/src/coquic_steward/publication/pipeline.py:342-480`). It can therefore
perform Python work, filesystem/staging work, external scanner work, and image
processing in one synchronous call.

There is no end-to-end monotonic deadline, cancellation token, process-group
cleanup contract, or timeout-specific publication outcome. A thread that stops
waiting would not cancel Python work or reliably terminate scanner/OCR child
processes, so a real deadline needs cooperative cancellation and explicit
cleanup at every owned boundary.

### Failure, retry, and compatibility evidence

- The publication `ReasonCode` vocabulary includes scanner and OCR failures,
  unsafe content, invalid metadata, changing input, and other bounded
  categories, but no build-timeout category
  (`steward/src/coquic_steward/publication/models.py:58-90`).
- Composition returns `RepairRequired`, `FailClosed`, or a bounded failure;
  unexpected builder errors are reduced to `invalid_metadata`. There is no
  current rule saying whether an elapsed build budget should fail closed,
  request repair, hide an existing head, block the outbox, or retry.
- The publisher treats `network`, `quota`, `timeout`, and `transient` as
  provider retry categories. That `timeout` is an existing transport/outbox
  category and must not be silently reused for local build expiry
  (`steward/src/coquic_steward/publication/publisher.py:73-95`).
- Provider retries are durable and bounded by `max_retries`; a completion-hook
  exception is deferred to daemon reconciliation, and CLI retry rebuilds
  current evidence. None of these paths supplies build-timeout semantics.
- Retiring the key makes configurations containing it fail the strict unknown-key
  check, including retained copies of the example. Keeping it while accepting
  and ignoring it would preserve parsing but create an explicit
  deprecation/observability contract; the accepted transition does not do so.
- A migration would need a target spelling or removal policy, support window,
  fleet/rollback behavior, and a way to update existing strict configurations.
  This repository evidence does not provide operator configuration contents,
  telemetry, or credentials; the accepted zero-release transition instead
  requires operators to remove the key before upgrading.

## Option matrix

The matrix records the accepted retirement decision and rejected alternatives. It
does not authorize runtime deadline changes.

| Direction | Candidate shape | Decision and rationale |
|---|---|---|
| **Retirement** | **Immediate removal/rejection.** Delete the field from the dataclass, parser allowlist/default, and example in one compatibility transition. | **Accepted.** The first changed release rejects retained keys through strict parsing; operators remove the key before upgrading. The previous release accepts omission, which provides rollback. |
| **Retirement** | **Accepted-but-ignored deprecation.** Keep parsing the key while making its lack of effect explicit. | Rejected. It would preserve a misleading configuration promise and require a warning period and final removal release. |
| **Retirement** | **Migration.** Rewrite existing configurations to a chosen replacement or remove the key under a controlled upgrade. | Rejected. No replacement target or migration tool is needed or authorized; the zero-release transition requires operators to remove the key. |
| **Implementation** | **Real end-to-end deadline.** Define one monotonic budget for the complete composition boundary, or explicitly choose a narrower documented phase. | Must specify whether graph capture, conversion, sanitization, scanner/OCR, staging, and cleanup are included; which callers enforce it; and whether disabled publication still validates the value. A stop-waiting-only wrapper is rejected because it does not cancel owned work. |
| **Implementation** | **Cancellation and cleanup.** Propagate cancellation/deadline through Python stages, scanner/OCR runners, temporary directories, staging descriptors, and child process groups. | Requires cancellable runner APIs, process termination/escalation rules, cleanup-after-timeout guarantees, and crash/restart behavior. A timed-out worker must not leave unowned child processes, partial staging, or an ambiguous outbox row. |
| **Implementation** | **Failure and retry contract.** Add a stable timeout outcome and decide how it interacts with fail-closed publication, existing visible heads, repair, outbox state, CLI retry, and provider retry budgets. | Requires a public reason category or an explicit existing category, durable evidence without leaking details, whether timeout consumes a retry, whether a retry reuses the deterministic generation, and how repeated expiry becomes blocked. Provider/network timeouts remain separate. |

A real implementation is more than a timer around the composer: it is a
cross-boundary cancellation, cleanup, failure, and retry contract. The
implementation option must not reinterpret scanner, OCR, network, lease, or
Codex stage timeouts as this deadline.

## Accepted decision

Retire `build_timeout_seconds` rather than invent incomplete deadline semantics.
The compatibility transition is immediate rejection with a zero-release
deprecation window. The implementation removes the dataclass field, parser
allowlist/default, and example entry; retained keys fail through strict
unknown-key validation. Operators remove the key before upgrading, and the
previous release accepts the same key-free configuration for rollback.

No warning period, silent-ignore path, automatic rewrite, fleet migrator, or
compatibility alias exists. This change does not add a timer or change
publication composition, provider, outbox, cleanup, or retry behavior. A future
deadline requires the separately defined cancellation, cleanup, failure, and
retry contract below.

## Deferred implementation questions

A future deadline requires answers to the following questions before any
runtime work is planned:

1. What exact wall-clock boundary does “build” cover: graph capture, conversion,
   redaction, scanner/OCR, staging, cleanup, or some subset? Is the budget
   monotonic and per generation, per caller, or per task?
2. Which synchronous callers must enforce the same contract: session completion,
   daemon queue/reconciliation, terminal receipt verification, and CLI retry? Is
   a retry granted a fresh budget?
3. On expiry, should publication fail closed, request repair, hide an existing
   visible head, remain queued, or become blocked? What stable reason and
   operator-facing evidence are required?
4. Does expiry consume `max_retries`, or is build retry independent from
   provider/network retry? Should retries reuse the same deterministic
   generation identity or create a changed generation?
5. What cancellation guarantee is required for scanner/OCR subprocesses, Python
   work, temporary files, and staging children, including escalation after a
   process ignores termination?
6. Which cleanup and restart invariants must be proven before a timed-out
   composition can be retried, and how should an interrupted cleanup be
   represented durably?
7. Is any operator configuration inventory or telemetry needed to select a
   future support policy? This record does not inspect credentials or private
   configuration contents.

## Bounded follow-up shape

A future end-to-end build deadline is a separate contract. It must define the
deadline boundary and monotonic propagation, add cancellable scanner/OCR and
child-process runners with cleanup invariants, choose a stable failure and
outbox/CLI retry policy, cover every composition caller, and add focused
timeout/restart tests. Keep network, lease, scanner/OCR, and Codex stage
timeouts as separate contracts.

## Verification record

The pre-retirement evidence searches were reproduced against the assigned tree:

- `git grep -n 'build_timeout_seconds' -- steward/src steward/steward.example.toml steward/tests` — only configuration and example references.
- `git grep -n 'compose_publication_generation' -- steward/src/coquic_steward steward/tests` — session, daemon, publisher, and tests are visible.
- `git grep -n -E 'scanner_timeout|ocr_timeout|network_timeout_seconds|lease_duration_seconds' -- steward/src/coquic_steward/publication steward/src/coquic_steward/orchestration steward/src/coquic_steward/cli.py` — separate stage, provider, and lease owners are visible.
- `git log --oneline -S'build_timeout_seconds' -- steward` — introduction commit `ee94b9fd feat(steward): configure cloud publication`.

The source/example inventory, removed-key test, focused/full tests, hooks, and
hygiene checks verify this retirement transition.
