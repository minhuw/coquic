# Self Interop Workflow Design

## Summary

Add one new GitHub Actions job to [`.github/workflows/interop.yml`](/home/minhu/projects/coquic/.github/workflows/interop.yml) that runs the official interop runner with `coquic` as both implementations. The job should execute exactly once, cover the full official testcase set already exercised across the existing peer jobs, and upload its logs under a distinct artifact name.

## Goals

- Add explicit self-interop coverage to CI.
- Reuse the existing official-runner flow and existing `interop/run-official.sh` contract.
- Run the self-interop case once, not twice, to avoid redundant CI cost.
- Keep the workflow change additive and easy to review.

## Non-Goals

- Refactor the workflow into a matrix.
- Change existing `interop-quicgo` or `interop-picoquic` behavior.
- Modify [`interop/run-official.sh`](/home/minhu/projects/coquic/interop/run-official.sh).
- Introduce new workflow inputs, scripts, or test filtering logic.

## Workflow Shape

Add a third job named `interop-self` beside the existing official-runner jobs.

The new job should reuse the same step structure:

- checkout
- Nix install
- Magic Nix Cache
- Docker setup
- Docker version display
- official interop run via `nix develop -c bash interop/run-official.sh`
- artifact upload

The new job should set:

- `INTEROP_PEER_IMPL=coquic`
- `INTEROP_PEER_IMAGE=coquic-interop:quictls-musl`
- `INTEROP_DIRECTIONS=coquic-server`

Using `INTEROP_DIRECTIONS=coquic-server` is required to prevent duplicate self-runs. In the current runner wrapper, `both` would invoke `run_direction coquic coquic` twice under symmetric labels that collapse to the same logical pairing.

## Testcase Set

The self job should run the full official testcase superset already represented in the current workflow:

`handshake,handshakeloss,transfer,keyupdate,transferloss,handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,amplificationlimit,rebind-port,rebind-addr,connectionmigration`

This matches the broader coverage currently used for `picoquic` and avoids adding a separate “self-only” policy.

## Outputs And Failure Behavior

The job should upload logs as `interop-logs-self`.

Failure behavior should remain whatever [`interop/run-official.sh`](/home/minhu/projects/coquic/interop/run-official.sh) already enforces:

- missing results JSON
- missing requested testcase results
- testcase result not equal to `succeeded`
- missing testcase log directories
- runner or Docker process failures

## Verification

Implementation is complete when:

- the workflow YAML remains valid
- `interop-self` is present and structurally matches the existing jobs
- the self job runs exactly once through `INTEROP_DIRECTIONS=coquic-server`
- the self job uses the agreed full testcase list
- the self job uploads `interop-logs-self`
- the existing peer jobs remain unchanged except for surrounding file context

## Risks

- The self job adds CI runtime, especially because it uses the full testcase set.
- Self-interop can hide bugs that only appear against external implementations, so this job complements rather than replaces `quic-go` and `picoquic`.
