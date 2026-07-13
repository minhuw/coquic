# Steward Dashboard Migration

Status: In Progress
Date: 2026-07-13
Last updated: 2026-07-13

Current execution state: subplans 00 through 19 and Round 2 subplans 21
through 24 are complete locally on `main`. Subplans 20 and 25 are in progress;
subplan 26 is blocked on them. The deployed target has not yet received the
committed v3 site and mirror. The latest local artifact-path and clock-skew
review findings are fixed and covered by regression tests. The capability
matrix is checked in at [00-capability-matrix.md](00-capability-matrix.md), and
the v3 contract is checked in at `steward/schema/fixtures/public-monitor-v3/`.

## Objective

Remove the local Steward FastAPI and Next.js dashboard stack. Steward becomes
an outbound-only daemon controlled through its CLI, while `site/next` becomes
the only dashboard and monitors sanitized state published by the daemon.

## Target Architecture

```text
local operator
    |
    v
Steward CLI ------> SQLite, wakeups, and task artifacts
                         ^
                         |
                   Steward daemon
                         |
                         v
              public mirror projector
                         |
                  atomic SSH/rsync
                         |
                         v
                site/next dashboard
```

The site is read-only. It must not gain an authenticated or unauthenticated
control channel back to the daemon as part of this migration.

## Scope

- Make the public mirror a versioned and observable daemon-monitoring contract.
- Complete monitoring parity in `site/next` before deleting the local UI.
- Move every retained operator action to safe CLI commands.
- Harden public redaction, artifact limits, cache behavior, and schema handling.
- Remove `steward/web-ui`, `coquic_steward.web`, and their dependencies.

## Non-Goals

- Remote task creation or daemon control from the public site.
- Publishing unredacted prompts, environment data, credentials, or local paths.
- Replacing SQLite or the scheduler wakeup mechanism.
- Reworking unrelated site pages or the Steward task execution pipeline.
- Preserving every local debugger convenience when it is unsafe to publish.

## Round 2 Scope

Round 2 hardens the migrated architecture rather than reopening local dashboard
functionality. It adds continuous deletion guards, explicit HTTP behavior for
public artifacts, a repeatable schema-evolution gate, keyboard and accessibility
coverage, and deployed synthetic checks. Remote control, private artifact
publication, and a second dashboard remain out of scope.

## Migration Gates

1. The site shows active progress within 60 seconds of a stored state change.
2. The site distinguishes live, delayed, stale, offline, and incompatible data.
3. The public schema has producer and consumer contract tests.
4. Public mode cannot expose raw transcripts without an explicit private-target
   design outside this migration.
5. CLI commands cover scheduler wakeup, signal fetch, task enqueue, task status,
   task timeline, invariant audit, and safe direct execution.
6. A shadow run proves monitoring parity before local web code is removed.
7. Steward continues executing when the site or publisher is unavailable.

## Release Evidence

Local verification completed on 2026-07-13 after subplan 19:

- Steward retained suite: `221 passed`; public schema and mirror contract:
  `20 passed`.
- `coquic-steward --help` and `daemon --once --no-plan --no-dispatch` ran with
  a Node-free `PATH`; the daemon reported a headless cycle and exited cleanly.
- Site typecheck, Vitest, and production build passed; Vitest reported `45`
  tests and Playwright reported `8` desktop/mobile monitor flows.
- `zig build` and `zig build test` passed; the native suite reported `1,757`
  tests passed. `goodput` and `crosstraffic` were not run.
- Schema generation check, local redaction scan, and repository pre-commit
  hooks passed. No tracked local dashboard files or generated build state
  remain in the worktree.
- Toolchain versions: Zig `0.16.0`, Python `3.13.13`, uv `0.8.5`, Node
  `v25.2.1`, and npm `11.6.2`. The local atomic writer race check passed 10
  consecutive times; remote publish latency remains unmeasured until deploy.
- Cutover commit range: `216018d9..166df7b2`. The immediate rollback point is
  `7eea3ec5` (`docs(steward): record dashboard shadow rollout`); disable
  `public_mirror.enabled` and `public_mirror.publish`, then restart Steward to
  stop public generation and upload without stopping local task execution.

The deployed target still needs a deployment update before the final migration
gate can be closed. The read-only synthetic run on 2026-07-13 observed the
dashboard at `200`, `/steward/status` at `404`, and the legacy
`/steward/status.json` at `200` with `schema_version = 2`; no remote deployment
state was changed. The follow-up is to deploy the committed site and mirror,
then verify the canonical route, v3 payload, freshness headers, task artifact,
latency, and redaction scan against the deployed files.

## Round 2 Release Evidence

Local implementation evidence was recorded on 2026-07-13 for subplans 21
through 25 and the local portion of subplan 26. The latest review findings for
artifact-path containment and mixed future timestamps are now fixed:

- Implementation commits: `15042338`, `e258a6cd`, `efa51579`, `33d6c7bc`,
  `c45627b6`, `0d340fc8`, `d9f2cd81`, and `50e7ed45`. The last two commits
  close the artifact-path and clock-skew review findings.
- `nix develop -c uv run --project steward python -m pytest steward/tests -q`:
  `288 passed`, including `10` synthetic monitor fixture tests.
- `nix develop -c uv run --project steward python steward/schema/generate_types.py --check`,
  the migration guard, and the isolated no-Node smoke test passed.
- In `site/next`: `npm run typecheck`, `npm test -- --reporter=dot`,
  `npm run build`, and `npm run test:e2e -- --reporter=line` passed; Vitest
  reported `55 passed` and Playwright reported `12 passed` across desktop and
  mobile projects, including serious axe checks and keyboard-only flows.
- `nix develop -c zig build` and `nix develop -c zig build test` passed;
  `goodput` and `crosstraffic` were not run. Repository pre-commit hooks passed
  for the final implementation.
- The production synthetic command was run read-only with
  `--base-url https://coquic.minhuw.dev`; the result was sanitized and showed
  dashboard success plus the expected canonical-route `404`. No secret or
  response body was printed, and no daemon or remote deployment state changed.

Subplan 26 is blocked until subplans 20 and 25 complete. After deployment,
rerun the synthetic command and archive its JSON artifact, then record the
response age, latency, canonical headers, task artifact result, and redaction
result here before closing the gate.

## Latest Progress Review

Review snapshot: 2026-07-13 after `50e7ed45`; the only worktree change is this
tracker update.

- A fresh read-only production synthetic run returned `200` for the dashboard;
  dashboard headers, privacy, and latency passed (`1412.857 ms` against the
  `2000 ms` limit).
- The canonical `/steward/status` route still returned `404`, so schema,
  freshness, privacy, and task-artifact checks could not run against production.
- Subplan 22 is complete locally in `d9f2cd81`; exact dot segments, encoded dot
  requests, and resolved artifact containment are covered by route tests.
- Subplan 25's mixed future-clock case is complete locally in `50e7ed45`; each
  timestamp is checked independently before stale-age calculation.
- Subplan 26 is blocked until subplans 20 and 25 complete and a sanitized
  passing production artifact is recorded.

## Dependency Graph

```mermaid
flowchart LR
    P00[00 Inventory] --> P01[01 Public contract]

    P01 --> P02[02 Runtime heartbeat]
    P01 --> P03[03 Publish health]
    P01 --> P04[04 Cache-safe status route]
    P01 --> P05[05 Schema and TS types]
    P01 --> P09[09 Public data hardening]

    P00 --> P10[10 CLI tick command]
    P00 --> P11[11 CLI run locking]

    P02 --> P06[06 Freshness UI]
    P04 --> P06
    P05 --> P06

    P01 --> P07[07 Planner history]
    P05 --> P07
    P00 --> P08[08 Read-view parity]
    P05 --> P08

    P02 --> P13[13 Producer contract tests]
    P03 --> P13
    P05 --> P13
    P09 --> P13

    P04 --> P14[14 Site monitor tests]
    P05 --> P14
    P06 --> P14
    P07 --> P14
    P08 --> P14

    P02 --> P12[12 Operator docs]
    P03 --> P12
    P09 --> P12
    P10 --> P12
    P11 --> P12

    P06 --> P15[15 Shadow rollout]
    P07 --> P15
    P08 --> P15
    P09 --> P15
    P10 --> P15
    P11 --> P15
    P12 --> P15
    P13 --> P15
    P14 --> P15

    P15 --> P16[16 Daemon cutover]
    P16 --> P17[17 Remove Python web]
    P16 --> P18[18 Remove local Next UI]
    P17 --> P19[19 Dependency cleanup]
    P18 --> P19
    P19 --> P20[20 Final verification]
```

## Round 2 Dependency Graph

```mermaid
flowchart LR
    P19[19 Dependency cleanup] --> P21[21 Migration regression guard]
    P14[14 Site monitor tests] --> P22[22 Artifact HTTP contract]
    P05[05 Schema ownership] --> P23[23 Schema evolution gate]
    P13[13 Producer contracts] --> P23
    P14 --> P23
    P14 --> P24[24 Accessibility and keyboard]

    P20[20 Final verification] --> P25[25 Deployed synthetic monitor]
    P22 --> P25
    P23 --> P25

    P21 --> P26[26 Round 2 verification]
    P22 --> P26
    P23 --> P26
    P24 --> P26
    P25 --> P26
```

## Round 1 Execution Waves

| Wave | Subplans | Parallel Opportunity |
| --- | --- | --- |
| 0 | 00, then 01 | Establish facts and freeze the contract first. |
| 1 | 02, 03, 04, 05, 09, 10, 11 | Seven independent workstreams after the contract; CLI work can start after inventory. |
| 2 | 06, 07, 08, 13 | Site views and producer tests can run concurrently. |
| 3 | 12, 14 | Documentation and site testing are independent once their inputs land. |
| 4 | 15 | Single coordinated shadow-run gate. |
| 5 | 16 | Switch the daemon entrypoint only after the gate passes. |
| 6 | 17, 18 | Python web removal and local Next.js removal can run in parallel branches. |
| 7 | 19, then 20 | Consolidate dependencies, then perform final verification. |

## Round 2 Execution Waves

| Wave | Subplans | Start Condition |
| --- | --- | --- |
| A | 22, 23, 24 | Complete locally; route, schema, and accessibility gates pass. |
| B | 21 | Complete after subplan 19 removed the final web-only dependencies. |
| C | 25 | In progress; local clock-skew coverage passes and the deployed v3 route remains open. |
| D | 26 | Blocked until 20 and 25 pass. |

## Subplan Index

| ID | Subplan | Depends On | Status |
| --- | --- | --- | --- |
| 00 | [Current-state inventory](00-current-state-inventory.md) | None | Complete |
| 01 | [Public monitoring contract](01-public-monitoring-contract.md) | 00 | Complete |
| 02 | [Daemon runtime heartbeat](02-daemon-runtime-heartbeat.md) | 01 | Complete |
| 03 | [Publisher health and retry state](03-publisher-health.md) | 01 | Complete |
| 04 | [Cache-safe site status endpoint](04-cache-safe-status-endpoint.md) | 01 | Complete |
| 05 | [Schema and TypeScript ownership](05-schema-and-types.md) | 01 | Complete |
| 06 | [Freshness and offline UI](06-site-freshness-ui.md) | 02, 04, 05 | Complete |
| 07 | [Standalone planner history](07-site-planner-history.md) | 01, 05 | Complete |
| 08 | [Read-view parity](08-site-read-view-parity.md) | 00, 05 | Complete |
| 09 | [Public data hardening](09-public-data-hardening.md) | 01 | Complete |
| 10 | [CLI scheduler tick](10-cli-scheduler-tick.md) | 00 | Complete |
| 11 | [CLI direct-run locking](11-cli-run-locking.md) | 00 | Complete |
| 12 | [Configuration and operator docs](12-operator-docs-and-config.md) | 02, 03, 09, 10, 11 | Complete |
| 13 | [Producer contract tests](13-producer-contract-tests.md) | 02, 03, 05, 09 | Complete |
| 14 | [Site monitor tests](14-site-monitor-tests.md) | 04, 05, 06, 07, 08 | Complete |
| 15 | [Shadow rollout](15-shadow-rollout.md) | 06-14 as graphed | Complete |
| 16 | [Daemon entrypoint cutover](16-daemon-entrypoint-cutover.md) | 15 | Complete |
| 17 | [Remove Python web runtime](17-remove-python-web-runtime.md) | 16 | Complete |
| 18 | [Remove local Next.js UI](18-remove-local-next-ui.md) | 16 | Complete |
| 19 | [Dependency and documentation cleanup](19-dependency-cleanup.md) | 17, 18 | Complete |
| 20 | [Final verification and release](20-final-verification.md) | 19 | In Progress |

## Round 2 Task Tracker

This table is the live source of truth for Round 2. `Ready` means dependencies
are complete and an implementer can claim the task. `Pending` means at least
one dependency is still open. `In Progress` and `Complete` include evidence
only after the corresponding local checks pass.

| ID | Subplan | Depends On | Status | Owner | Implementation Evidence |
| --- | --- | --- | --- | --- | --- |
| 21 | [Continuous migration regression guard](21-continuous-migration-guard.md) | 19 | Complete | Codex | `33d6c7bc`; guard, negative self-tests, and no-Node smoke passed. |
| 22 | [Public artifact HTTP contract](22-public-artifact-http-contract.md) | 14 | Complete | Codex | `15042338`, `d9f2cd81`; headers, dot segments, encoded requests, and containment tests pass. |
| 23 | [Schema evolution and compatibility gate](23-schema-evolution-gate.md) | 05, 13, 14 | Complete | Codex | `e258a6cd`; generated drift, compatibility fixtures, and deliberate bump gate passed. |
| 24 | [Monitor accessibility and keyboard behavior](24-monitor-accessibility-keyboard.md) | 14 | Complete | Codex | `efa51579`, `c45627b6`; axe, keyboard, focus, and 12 desktop/mobile flows passed. |
| 25 | [Deployed synthetic monitor](25-deployed-synthetic-monitor.md) | 20, 22, 23 | In Progress | Codex | `0d340fc8`, `50e7ed45`; fixture suite and mixed future-skew gate pass; production v3 remains open. |
| 26 | [Round 2 verification](26-round-two-verification.md) | 21-25 | Blocked | Codex | Local matrix passes; waiting for 20, 25, and a passing production artifact. |

## Coordination Rules

- Each subplan should land as one Conventional Commit unless its validation
  requires a preparatory test-only commit.
- A subplan may start only when all listed dependencies are merged.
- Parallel branches must avoid editing shared schema and generated type files
  without coordinating through subplan 05.
- Subplans 17 and 18 must not edit `steward/README.md`; subplan 19 owns the
  final dependency and documentation consolidation.
- Update this index as subplans move through Pending, Ready, In Progress,
  Blocked, and Complete.
- For Round 2, set the tracker owner and change `Ready` to `In Progress` before
  implementation. Record commit and validation evidence only after checks pass.
- Keep implementation commits self-contained and exclude
  `plans/dashboard-migrations`; land task-tracking updates separately.
