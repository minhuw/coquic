# GitHub Interop Picoquic Peer Design

## Status

Approved in conversation on 2026-03-23.

## Goal

Add `picoquic` as a second official-runner peer in GitHub interop CI while
keeping the existing `quic-go` coverage.

The outcome should be:

- GitHub interop CI runs one job against `quic-go`
- GitHub interop CI runs a second job against `picoquic`
- both jobs request the exact same testcase and measurement slice
- the repo-local wrapper stays single-sourced instead of forking into
  peer-specific copies

## Context

The current GitHub workflow and local wrapper are still biased toward a single
peer implementation:

- the workflow exposes one job named for `quic-go`
- the wrapper hardcodes `quic-go` as the non-`coquic` implementation
- the wrapper patches only the `quic-go` image entry in the pinned official
  runner manifest
- the wrapper runs only `coquic <-> quic-go`

That is enough for the current smoke coverage, but it means adding `picoquic`
would otherwise require either:

- duplicating the wrapper logic
- or generalizing the wrapper to accept a peer implementation identity

The pinned official runner manifest at ref
`97319f8c0be2bc0be67b025522a64c9231018d37` already includes:

- implementation key: `picoquic`
- official image: `privateoctopus/picoquic:latest`
- role: `both`

So the missing support is repo-owned workflow and wrapper parameterization, not
runner-level implementation discovery.

## Scope

This design covers:

- `.github/workflows/interop.yml`
- `tests/nix/interop_runner_test.sh`
- `tests/nix/github_interop_workflow_test.sh`
- `tests/nix/official_interop_runner_contract_test.sh`

## Non-Goals

- changing `coquic` runtime behavior
- changing the pinned official runner ref
- changing testcase selection differently for `picoquic` than for `quic-go`
- introducing a workflow matrix if explicit peer jobs remain readable
- adding new peers beyond `quic-go` and `picoquic`

## Decisions

### 1. Keep Explicit Peer Jobs In The Workflow

The workflow will have two explicit jobs:

- job id `interop-quicgo` for `quic-go`
- job id `interop-picoquic` for `picoquic`

Rationale:

- keeps GitHub Actions logs and failures easy to read
- preserves the current workflow shape closely
- avoids making the workflow contract test parse matrix expansion semantics

### 2. Reuse One Parameterized Local Wrapper

`tests/nix/interop_runner_test.sh` will remain the single repo-owned adapter
between GitHub/Nix execution and the pinned official runner.

It will be generalized with required environment variables for the non-`coquic`
peer:

- `INTEROP_PEER_IMPL`
- `INTEROP_PEER_IMAGE`

The wrapper will use those values to:

- patch the corresponding entry in `implementations_quic.json`
- pull the correct peer image
- run `coquic` against that peer in both directions

Rationale:

- one wrapper means one place to keep CI fixes and runner-contract workarounds
- avoids duplicating the official-runner JSON validation logic

### 3. Keep The Testcase Slice Exactly The Same For Both Peers

Both jobs will request the same slice:

- `handshake`
- `handshakeloss`
- `transfer`
- `transferloss`
- `handshakecorruption`
- `transfercorruption`
- `chacha20`
- `longrtt`
- `goodput`
- `crosstraffic`

Rationale:

- matches the approved user requirement exactly
- keeps coverage comparable across peers
- avoids peer-specific drift in workflow expectations

### 4. Keep `coquic` Image Handling Unchanged

The current `coquic` container and package selection remain:

- `coquic-interop:quictls-musl`
- `interop-image-quictls-musl`

This design changes only the peer-side implementation selection.

### 5. Extend Repo Contract Tests To Pin Peer Parameterization

The repo tests should prevent regressions by pinning:

- the presence of both workflow jobs
- the exact workflow job ids and human-facing job names
- distinct artifact names per job
- the exact shared testcase string in both jobs
- the wrapper fragments that read peer implementation and peer image from env
- the wrapper behavior that patches the chosen implementation entry instead of
  hardcoding only `quic-go`

## Architecture

### Workflow Layer

`interop.yml` remains a straightforward multi-job workflow.

Each job will:

- verify the workflow contract
- set the shared `INTEROP_TESTCASES` string
- set peer-specific env with exact values:
  - `INTEROP_PEER_IMPL=quic-go`
  - `INTEROP_PEER_IMAGE=martenseemann/quic-go-interop@sha256:919f70ed559ccffaeadf884b864a406b0f16d2bd14a220507e83cc8d699c4424`
  - `INTEROP_PEER_IMPL=picoquic`
  - `INTEROP_PEER_IMAGE=privateoctopus/picoquic:latest`
- invoke `nix develop -c bash tests/nix/interop_runner_test.sh`

Each job will upload logs under a distinct artifact name:

- `interop-logs-quicgo`
- `interop-logs-picoquic`

### Wrapper Layer

`tests/nix/interop_runner_test.sh` will:

1. read peer implementation name and peer image from env
2. patch the pinned runner manifest entry matching that implementation key
3. pull the selected peer image
4. run:
   - `server=coquic client=<peer>`
   - `server=<peer> client=coquic`
5. keep the existing JSON/result/measurement/log validation behavior

The wrapper should fail fast if:

- `INTEROP_PEER_IMPL` is unset or empty
- `INTEROP_PEER_IMPL` names an implementation absent from the pinned runner
  manifest
- the selected peer image is empty

### Contract Test Layer

The workflow contract test should pin:

- both job names
- both artifact names
- both peer env blocks
- the shared testcase string

The wrapper contract test should pin:

- env-driven peer selection fragments
- manifest patching by selected implementation key
- peer image pull by selected image variable
- absence of hardcoded single-peer-only logic where inappropriate

## Error Handling

The wrapper should emit explicit failures when:

- the selected peer implementation key is missing from
  `implementations_quic.json`
- the runner JSON is missing
- the runner JSON shape is wrong
- a requested testcase or measurement result is missing or unsuccessful
- the expected per-requested-name log directory is missing

Failure wording should keep CI logs actionable enough to distinguish:

- workflow contract drift
- wrong peer wiring
- pinned runner manifest drift
- actual interop failure against `picoquic` or `quic-go`

## Testing

### Repo Tests

Update:

- `tests/nix/github_interop_workflow_test.sh`
- `tests/nix/official_interop_runner_contract_test.sh`

### Verification

Minimum verification for implementation:

- run the workflow contract test
- run the wrapper contract test
- run a local wrapper sanity invocation for the `picoquic` wiring
- run the main test suite if shared wrapper behavior changes materially

## Risks

### 1. `picoquic` Image Behavior May Differ From `quic-go`

Even with identical testcase requests, the peer container may expose different
compliance quirks or performance characteristics.

Mitigation:

- keep the workflow job separate so failures are attributable per peer
- verify local wrapper wiring before depending on GitHub CI

### 2. Wrapper Parameterization Could Regress Existing `quic-go` Coverage

Generalizing the wrapper introduces a risk of breaking the existing `quic-go`
path while adding `picoquic`.

Mitigation:

- keep repo contract tests explicit about both peers
- preserve current defaults or explicitly set `quic-go` in the workflow job

### 3. Upstream Runner Manifest Keys Could Drift

If the pinned runner changes implementation keys or image fields in the future,
env-driven patching could fail.

Mitigation:

- scope the design to the currently pinned runner ref
- fail explicitly if the selected implementation key is absent
