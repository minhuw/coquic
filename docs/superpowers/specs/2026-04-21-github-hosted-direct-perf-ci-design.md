## GitHub Hosted Direct Perf CI Design

Date: 2026-04-21
Repo: `coquic`
Status: Draft

## Summary

Replace the current Docker-based `perf.yml` benchmark execution with direct
hosted-runner execution of the `coquic-perf` binary, while keeping the workflow
GitHub-hosted, advisory, and artifact-compatible with the current summary
renderer.

The workflow should continue to run on:

- `pull_request`
- `push` to `main`

It should keep the existing CI benchmark tuples and artifact layout, but stop
building and running a Docker image. Instead, the repo-owned harness should
build an optimized `coquic-perf` binary once via Nix, pin the server and client
processes to fixed CPUs with `taskset`, run the benchmark matrix directly on the
runner host, and emit the same `.bench-results/manifest.json` plus per-run
`.json` and `.txt` files used by the current summary flow.

## Problem

The current advisory performance workflow in
[perf.yml](/home/minhu/projects/coquic/.github/workflows/perf.yml) measures a
containerized workload, not the direct process execution path used for local
profiling and optimization.

Recent investigation showed two important effects:

1. the current Docker harness materially lowers measured throughput relative to
   direct execution, even on the same machine
2. GitHub-hosted runner pools still introduce noise, but Docker adds another
   large and avoidable distortion on top of that noise

That makes the current workflow less useful for judging whether direct QUIC hot
path optimizations improved the code that local `perf` and flamegraph work is
actually targeting.

## Goals

- Keep the workflow on GitHub-hosted `ubuntu-latest`.
- Remove Docker from benchmark execution in `perf.yml`.
- Keep the benchmark workflow advisory rather than threshold-gated.
- Preserve the current CI benchmark tuples:
  - `bulk`
  - `rr`
  - `crr`
- Preserve the current result shape:
  - `.bench-results/manifest.json`
  - per-run `.json`
  - per-run `.txt`
- Preserve the current job summary rendering path through
  [render-perf-summary.py](/home/minhu/projects/coquic/scripts/render-perf-summary.py).
- Keep the benchmark orchestration in a repo-owned script rather than inlining
  process management logic in workflow YAML.
- Keep local reproduction straightforward.

## Non-Goals

- No move to self-hosted runners in this change.
- No performance threshold enforcement or required-merge gating.
- No attempt to make GitHub-hosted numbers lab-grade stable.
- No change to the benchmark tuple definitions themselves.
- No addition of `perf record`, flamegraph generation, or profiler artifact
  capture to the workflow.
- No expansion to new benchmark modes or backends in this change.

## Decisions

### 1. Keep The Existing Harness Entry Point

Keep the repo-owned benchmark entry point at
[bench/run-host-matrix.sh](/home/minhu/projects/coquic/bench/run-host-matrix.sh),
but replace its internals from Docker orchestration to direct process
orchestration.

Rationale:

- preserves the current workflow call site
- preserves the current local command shape documented in the repo
- minimizes file and test churn

Consequence:

- the existing harness contract test must be updated to validate direct-host
  invariants instead of Docker-specific ones

### 2. Build One Optimized `coquic-perf` Binary Through Nix

The harness should build the optimized perf binary once before running the
matrix and reuse that binary across all benchmark cases.

Preferred source:

- `nix build --print-out-paths .#coquic-perf-quictls-musl`

The harness should then execute:

- `<out>/bin/coquic-perf server ...`
- `<out>/bin/coquic-perf client ...`

Rationale:

- matches the existing perf packaging path more closely than a dev-shell debug
  build
- avoids rebuilding per benchmark case
- keeps CI and local reproduction aligned around one packaged optimized binary

### 3. Run Server And Client Directly On The Hosted Runner

For each run tuple, the harness should:

1. start a pinned server process in the background
2. wait briefly for the listener to come up
3. run the pinned client process in the foreground
4. collect client stdout into the per-run `.txt` summary
5. ensure the server process is terminated during normal completion and failure
   cleanup

The harness should continue to use:

- loopback networking through `127.0.0.1`
- per-run JSON output via `--json-out`
- the current manifest aggregation step

Rationale:

- removes container runtime overhead from the measured path
- keeps the benchmark topology equivalent to the local host-direct perf work

### 4. Keep CPU Pinning With `taskset`

The harness should preserve CPU affinity control using fixed runner CPUs:

- server pinned to CPU `2`
- client pinned to CPU `3`

These should remain configurable through environment overrides, for example:

- `PERF_SERVER_CPUS`
- `PERF_CLIENT_CPUS`

The direct harness should use `taskset -c` when launching both processes.

Rationale:

- preserves the current intent of limiting scheduler drift between server and
  client
- keeps the CI setup close to the local direct benchmark shape already used for
  profiling

### 5. Preserve The Existing CI Run Matrix

The `ci` preset should keep the current tuples exactly:

- `socket bulk download 0 1048576 none 4 1 1 5s 60s`
- `socket rr stay 32 32 none 1 256 16 5s 45s`
- `socket crr stay 32 32 none 1 512 1 5s 45s`

This change is about execution environment, not workload semantics.

Rationale:

- isolates the measurement change to Docker removal
- keeps historical artifact comparisons meaningful enough for manual review

### 6. Preserve Artifact And Summary Compatibility

The direct harness must still write:

- per-run `.json`
- per-run `.txt`
- `.bench-results/manifest.json`

The manifest shape should remain compatible with
[render-perf-summary.py](/home/minhu/projects/coquic/scripts/render-perf-summary.py)
so the workflow summary step does not need a semantic redesign.

Rationale:

- avoids unnecessary workflow churn
- preserves existing artifact inspection habits

### 7. Add Lightweight Environment Fingerprinting

Because GitHub-hosted runners remain noisy and region-dependent even without
Docker, the harness should also emit a small environment snapshot artifact such
as `.bench-results/environment.txt`.

It should include stable, low-cost facts such as:

- `uname -a`
- `lscpu`
- `nproc`
- current affinity settings used for server and client

This file does not need to be included in the manifest. It only needs to be
uploaded with the other benchmark artifacts.

Rationale:

- makes future CI variance easier to interpret
- adds useful observability without changing benchmark semantics

### 8. Update Contract Tests To Match The Direct Harness

[tests/nix/perf_harness_test.sh](/home/minhu/projects/coquic/tests/nix/perf_harness_test.sh)
should stop asserting Docker-specific behavior such as:

- `docker load`
- `docker run`
- `--network host`
- container capability overrides

Instead, it should assert the new direct-host invariants, including:

- direct execution of `coquic-perf`
- `taskset -c` CPU pinning
- use of the fixture certificate and key paths
- per-run JSON output
- manifest generation
- preservation of the `smoke` and `ci` tuple definitions

[tests/nix/github_perf_workflow_test.sh](/home/minhu/projects/coquic/tests/nix/github_perf_workflow_test.sh)
should continue to validate the workflow triggers, artifact upload, and summary
steps, but keep expecting the existing harness invocation path.

## Data Flow

The resulting hosted-runner flow should be:

1. checkout repo
2. install Nix
3. run the perf harness contract test
4. build optimized `coquic-perf` once through Nix
5. run the `ci` preset through the direct-host harness
6. collect `.bench-results/*.json`, `.bench-results/*.txt`,
   `.bench-results/manifest.json`, and `.bench-results/environment.txt`
7. render the GitHub step summary from `manifest.json`
8. upload the benchmark artifacts

## Error Handling

The direct harness should continue to fail the job for real execution problems,
including:

- Nix build failure
- missing perf binary output path
- server startup failure
- missing per-run JSON result
- non-zero client exit
- malformed or missing manifest

The harness should always clean up background server processes on exit,
including when a client run fails midway through the matrix.

## Testing

Verification for this design should include:

1. update and pass
   [tests/nix/perf_harness_test.sh](/home/minhu/projects/coquic/tests/nix/perf_harness_test.sh)
2. update and pass
   [tests/nix/github_perf_workflow_test.sh](/home/minhu/projects/coquic/tests/nix/github_perf_workflow_test.sh)
3. run the direct harness locally on at least the `smoke` preset
4. confirm the workflow still publishes a readable summary from
   `manifest.json`
5. confirm uploaded artifacts include the expected per-run outputs and the
   environment snapshot

## Expected Outcome

After this change, the advisory GitHub-hosted perf workflow should still be
noisy, but it should be materially closer to the direct process performance that
local optimization and profiling work targets.

The workflow remains advisory rather than authoritative, but it should stop
paying the large extra distortion introduced by the current Docker-based
benchmark path.
