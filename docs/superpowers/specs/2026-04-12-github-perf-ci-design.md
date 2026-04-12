# GitHub Perf CI Design

Date: 2026-04-12
Repo: `coquic`
Status: Approved

## Summary

Add a separate GitHub Actions workflow dedicated to advisory performance
monitoring for `coquic-perf`.

The workflow should run on:

- `pull_request`
- `push` to `main`

It should reuse the existing repo-owned benchmark harness, execute the current
`smoke` preset on GitHub-hosted Linux runners, upload `.bench-results/`
artifacts, and publish a compact job summary derived from
`.bench-results/manifest.json`.

This workflow is intentionally advisory. It monitors benchmark behavior on every
PR and `main` push, but it does not enforce performance thresholds and it is not
intended to be a required merge gate.

## Problem

`coquic` now has a dedicated `coquic-perf` binary and a repo-owned smoke harness,
but there is no automated GitHub workflow that runs it continuously across
commits.

Without CI coverage for performance smoke runs:

- performance-visible regressions can land unnoticed until someone benchmarks
  locally
- contributors cannot easily inspect benchmark output from PRs
- `socket` and `io_uring` backend behavior is not continuously exercised through
  the benchmark surface

At the same time, GitHub-hosted runners are noisy virtualized environments. That
means the workflow must be designed for observability, not for precise
regression gating.

## Goals

- Add a dedicated performance workflow separate from the main correctness CI.
- Run benchmark smoke coverage on every PR and every push to `main`.
- Reuse the existing repo-owned benchmark harness:
  - `bash bench/run-host-matrix.sh --preset smoke`
- Cover the full current smoke matrix:
  - `bulk`
  - `rr`
  - `crr`
  - both `socket` and `io_uring`
- Publish benchmark outputs as GitHub Actions artifacts.
- Publish a readable benchmark summary directly in the workflow job UI.
- Keep the workflow advisory:
  - no benchmark thresholds
  - no PR comment bot
  - no nightly schedule
  - no third-party benchmark service

## Non-Goals

- No attempt to make GitHub-hosted measurements authoritative lab-quality
  performance numbers.
- No performance-based merge blocking in v1.
- No benchmark history service or external dashboard in v1.
- No nightly-only or scheduled benchmark workflow.
- No workflow-level PR comment publishing in v1.
- No new benchmark orchestration path separate from the repo-owned harness.
- No expansion beyond the existing smoke preset in the initial workflow.

## Decisions

### 1. Use A Separate Workflow

Add a new workflow, for example:

- `.github/workflows/perf.yml`

Do not fold benchmark execution into `ci.yml`.

Rationale:

- the benchmark path depends on Docker, Nix image building, and artifact
  handling
- keeping it separate preserves a clean correctness CI signal
- performance results remain visible without slowing or complicating the main
  build-and-test workflow unnecessarily

### 2. Trigger Only On PRs And Pushes To `main`

Workflow triggers:

- `pull_request`
- `push`:
  - branches:
    - `main`

Do not run on a nightly schedule in v1.

Rationale:

- the user explicitly wants commit-oriented monitoring, not a scheduled
  benchmark job
- avoiding nightly runs keeps CI cost and log volume predictable

### 3. Use GitHub-Hosted `ubuntu-latest`

Run the workflow on:

- `ubuntu-latest`

Do not require self-hosted or third-party benchmark infrastructure in v1.

Rationale:

- keeps setup and maintenance low
- matches the user’s decision to stay on GitHub CI only
- preserves a simple contribution model for forks and PRs

Consequence:

- results must be interpreted as advisory trend data rather than stable
  performance certification

### 4. Reuse The Existing Repo-Owned Smoke Harness

The workflow should call:

- `bash tests/nix/perf_harness_test.sh`
- `bash bench/run-host-matrix.sh --preset smoke`

Do not duplicate benchmark orchestration logic inside YAML.

Rationale:

- the harness already encodes the host-network, CPU-pinning, image-loading, and
  result-manifest behavior
- repo-owned scripts are easier to run locally when debugging CI differences
- YAML should orchestrate, not become the benchmark implementation

### 5. Run The Full Existing Smoke Matrix

The CI workflow should use the current `smoke` preset without reducing the
matrix further.

That means:

- `bulk`, `rr`, and `crr`
- `socket` and `io_uring`

Rationale:

- the existing smoke preset is already small enough for advisory CI
- it exercises both backend selection and all three benchmark modes
- reusing the exact local smoke preset avoids drift between local and CI paths

### 6. Treat The Workflow As Advisory, Not Threshold-Gated

In v1, do not compare runs against historical baselines and do not fail the job
for statistical regressions.

The workflow should still fail for real execution problems such as:

- Nix build failure
- image load failure
- harness contract test failure
- missing benchmark result files
- benchmark process failure

Rationale:

- numbers on GitHub-hosted runners will be noisy
- execution failures still indicate real breakage in the benchmark stack
- this preserves workflow usefulness without overclaiming measurement precision

Branch protection should therefore treat the workflow as optional rather than a
required status check.

### 7. Upload Full Result Artifacts

The workflow should upload `.bench-results/` with `if: always()`.

Artifacts should include:

- `manifest.json`
- per-run `.json` files
- per-run `.txt` summaries

Rationale:

- artifacts preserve the raw data for manual inspection
- text summaries and machine-readable JSON are both useful during debugging
- `if: always()` keeps failure evidence available when the benchmark job breaks

### 8. Publish A Job Summary Instead Of PR Comments

After the harness runs, the workflow should generate a GitHub job summary from
`.bench-results/manifest.json`.

The summary should include:

- event type
- commit SHA
- per-run mode
- backend
- elapsed time
- throughput
- requests per second
- latency percentiles where present
- status and failure reason if a run failed

Do not post or update PR comments in v1.

Rationale:

- job summaries are visible in the workflow UI without adding comment noise
- the user explicitly chose artifacts plus job summary, not PR comments

### 9. Preserve Current `io_uring` Behavior On Hosted Linux

The workflow should not special-case away `io_uring` smoke entries even if the
runner kernel falls back internally.

Expected behavior:

- benchmark requests the `io_uring` backend
- runtime may log fallback behavior if UDP `recvmsg` via `io_uring` is not
  supported on the runner kernel
- resulting artifacts and summaries still reflect the requested benchmark run

Rationale:

- the benchmark surface being exercised is still meaningful
- CI should monitor whether `io_uring` requests continue to run successfully in
  the hosted environment

## Workflow Shape

One job is sufficient in v1:

1. checkout repository
2. install Nix
3. optionally install or configure Docker only if required by hosted-runner
   behavior
4. run `bash tests/nix/perf_harness_test.sh`
5. run `bash bench/run-host-matrix.sh --preset smoke`
6. generate GitHub job summary from `.bench-results/manifest.json`
7. upload `.bench-results/` artifacts with `if: always()`

Recommended timeout:

- approximately `30` to `45` minutes

This leaves room for image build time plus benchmark execution without allowing
runaway jobs to hang indefinitely.

## Reporting Semantics

The workflow should communicate three things clearly:

- benchmark execution succeeded or failed
- what measurements were observed in this run
- where the raw artifacts are stored

It should not imply:

- strict cross-run comparability
- stable hardware calibration
- automatic performance regression judgment

Suggested summary framing:

- label the workflow as advisory performance monitoring
- mention GitHub-hosted runner variability explicitly
- treat the values as useful trend indicators and debugging evidence

## Future-Compatible Extensions

These are explicitly deferred, but the workflow should not block them later:

- adding a lightweight manifest-to-Markdown rendering helper script
- adding a historical comparison step against prior workflow artifacts
- moving the same harness to a self-hosted or bare-metal runner class
- adding a larger benchmark preset for manual `workflow_dispatch`

None of these are required for v1.
