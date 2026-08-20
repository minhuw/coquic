# Publication build-timeout contract

**Status:** non-binding decision packet

**Accepted:** no

**Runtime effect:** none. This packet changes no parser, configuration,
publication, retry, cancellation, or failure behavior.

## Evidence map

### Promised and actual configuration surface

- `StewardPublicationConfig.build_timeout_seconds` is a frozen configuration
  field with a `300.0` default. Its constructor validates it as a finite,
  positive value no greater than `86400` seconds and stores the normalized
  value (`steward/src/coquic_steward/core/config.py:362-510`).
- `_publication_config` includes `build_timeout_seconds` in its strict allowlist
  and supplies the same `300.0` default when loading TOML
  (`steward/src/coquic_steward/core/config.py:1254-1303`). Unknown keys are
  rejected rather than ignored.
- The example advertises `build_timeout_seconds = 300`
  (`steward/steward.example.toml:50`). The example configuration test loads
  the publication table successfully, while the configuration tests establish
  that unsupported publication keys fail (`steward/tests/test_example_config.py:12-23,193-210`).
- The exact repository inventory finds only parser/default/validation and
  example references. There is no read of the value by a publication caller,
  builder, provider client, retry policy, or test.
- History identifies `ee94b9fd feat(steward): configure cloud publication` as
  the introduction commit. That change added strict cloud publication settings
  and the example field, but did not establish deadline semantics or a
  consumer. Repository history cannot establish whether downstream operator
  configurations treat the accepted key as a supported promise.

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
- Removing the key immediately would make configurations containing it fail the
  strict unknown-key check, including retained copies of the example. Keeping
  it while accepting and ignoring it would preserve parsing but create an
  explicit deprecation/observability contract; that is not currently defined.
- A migration would need a target spelling or removal policy, support window,
  fleet/rollback behavior, and a way to update existing strict configurations.
  This repository evidence does not provide operator configuration contents,
  telemetry, or credentials and does not justify choosing that policy.

## Option matrix

The matrix compares the two legitimate directions without accepting either
one. It does not authorize runtime changes.

| Direction | Candidate shape | Consequences and decisions still required |
|---|---|---|
| **Retirement** | **Immediate removal/rejection.** Delete the field from the dataclass, parser allowlist/default, and example in one compatibility transition. | Existing files containing the key fail strict parsing. The support window, release note, migration/rollback story, and whether example-based deployments are expected to update atomically must be approved first. |
| **Retirement** | **Accepted-but-ignored deprecation.** Keep parsing the key while making its lack of effect explicit. | Avoids an immediate parse break but is a new compatibility promise and risks silently misleading operators. It needs warning/diagnostic behavior, an announced support window, and a final removal release. The current scope does not authorize silently ignoring or deprecating the key. |
| **Retirement** | **Migration.** Rewrite existing configurations to a chosen replacement or remove the key under a controlled upgrade. | Requires a canonical replacement/removal target, version detection, dry-run and rollback behavior, fleet coverage, and tests for mixed-version readers. No replacement target exists in the current contract. |
| **Implementation** | **Real end-to-end deadline.** Define one monotonic budget for the complete composition boundary, or explicitly choose a narrower documented phase. | Must specify whether graph capture, conversion, sanitization, scanner/OCR, staging, and cleanup are included; which callers enforce it; and whether disabled publication still validates the value. A stop-waiting-only wrapper is rejected because it does not cancel owned work. |
| **Implementation** | **Cancellation and cleanup.** Propagate cancellation/deadline through Python stages, scanner/OCR runners, temporary directories, staging descriptors, and child process groups. | Requires cancellable runner APIs, process termination/escalation rules, cleanup-after-timeout guarantees, and crash/restart behavior. A timed-out worker must not leave unowned child processes, partial staging, or an ambiguous outbox row. |
| **Implementation** | **Failure and retry contract.** Add a stable timeout outcome and decide how it interacts with fail-closed publication, existing visible heads, repair, outbox state, CLI retry, and provider retry budgets. | Requires a public reason category or an explicit existing category, durable evidence without leaking details, whether timeout consumes a retry, whether a retry reuses the deterministic generation, and how repeated expiry becomes blocked. Provider/network timeouts remain separate. |

A real implementation is more than a timer around the composer: it is a
cross-boundary cancellation, cleanup, failure, and retry contract. The
implementation option must not reinterpret scanner, OCR, network, lease, or
Codex stage timeouts as this deadline.

## Non-binding recommendation and routing

Do not change runtime behavior or configuration acceptance in this spike. Keep
the field and its current no-consumer behavior until Grill records the
compatibility choice and the intended meaning of “build.” On current evidence,
retirement appears lower risk than inventing an incomplete deadline, but even
retirement is not safe to execute without an explicit support window or
migration/accepted-deprecation decision. If an operator requirement truly needs
an end-to-end publication deadline, select the implementation shape instead and
commission a dedicated contract plan for cancellation, cleanup, failure, and
retry.

This recommendation is non-binding. It is not an acceptance of the field as a
semantic deadline, a deprecation, an accepted-and-ignored setting, or a promise
to implement it. Behavior and compatibility are routed to Grill; no existing
timeout is this deadline by implication.

## Questions for Grill

1. Is `build_timeout_seconds` an externally supported operator setting despite
   having no consumer, or is its current presence only an unfinished
   configuration surface?
2. If it is retired, should old configurations be rejected immediately,
   accepted with an explicit deprecation period, or migrated? What support
   window and rollback behavior apply to each release in the window?
3. If it is implemented, what exact wall-clock boundary does “build” cover:
   graph capture, conversion, redaction, scanner/OCR, staging, cleanup, or
   some subset? Is the budget monotonic and per generation, per caller, or per
   task?
4. Which synchronous callers must enforce the same contract: session
   completion, daemon queue/reconciliation, terminal receipt verification, and
   CLI retry? Is a retry granted a fresh budget?
5. On expiry, should publication fail closed, request repair, hide an existing
   visible head, remain queued, or become blocked? What stable reason and
   operator-facing evidence are required?
6. Does expiry consume `max_retries`, or is build retry independent from
   provider/network retry? Should retries reuse the same deterministic
   generation identity or create a changed generation?
7. What cancellation guarantee is required for scanner/OCR subprocesses,
   Python work, temporary files, and staging children, including escalation
   after a process ignores termination?
8. Which cleanup and restart invariants must be proven before a timed-out
   composition can be retried, and how should an interrupted cleanup be
   represented durably?
9. Is any operator configuration inventory or telemetry needed to select the
   compatibility window? This packet does not inspect credentials or private
   configuration contents.

## Bounded follow-up shapes

These are separately approvable shapes, not implementation authority:

1. **Retirement and compatibility transition.** Inventory supported versions
   and config consumers, choose immediate rejection versus explicit
   accepted-deprecation versus migration, define the support/rollback window,
   update the example and documentation, and add strict-parser/config tests.
   Do not add a runtime deadline or silently ignore the key without that
   decision.
2. **End-to-end build deadline.** Define the deadline boundary and monotonic
   propagation, add cancellable scanner/OCR/child-process runners and cleanup
   invariants, choose a stable failure and outbox/CLI retry policy, cover every
   composition caller, and add focused timeout/restart tests. Keep network,
   lease, scanner/OCR, and Codex stage timeouts as separate contracts.

## Verification record

The plan evidence searches were reproduced against the assigned tree:

- `git grep -n 'build_timeout_seconds' -- steward/src steward/steward.example.toml steward/tests` — only configuration and example references.
- `git grep -n 'compose_publication_generation' -- steward/src/coquic_steward steward/tests` — session, daemon, publisher, and tests are visible.
- `git grep -n -E 'scanner_timeout|ocr_timeout|network_timeout_seconds|lease_duration_seconds' -- steward/src/coquic_steward/publication steward/src/coquic_steward/orchestration steward/src/coquic_steward/cli.py` — separate stage, provider, and lease owners are visible.
- `git log --oneline -S'build_timeout_seconds' -- steward` — introduction commit `ee94b9fd feat(steward): configure cloud publication`.

The document gate and hygiene gate are run separately after this packet is
written. No code or test changes are part of this spike.
