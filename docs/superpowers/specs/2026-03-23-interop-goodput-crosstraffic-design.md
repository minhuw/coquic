# Interop Goodput And CrossTraffic Support Design

## Status

Approved in conversation on 2026-03-23.

## Goal

Add support for the official QUIC interop runner's `goodput` and
`crosstraffic` cases in this repo's GitHub interop workflow and local runner
wrapper.

The outcome should be:

- GitHub interop CI requests both cases
- the repo-local runner wrapper accepts them as valid requested names
- the wrapper validates them using the runner's measurement output instead of
  incorrectly treating them as ordinary testcase results

## Context

The current workflow and wrapper were built around ordinary official-runner
testcases such as:

- `handshake`
- `transfer`
- `transferloss`
- `chacha20`
- `longrtt`

That assumption leaks into the wrapper validation logic:

- requested names are looked up only in the runner's `results` matrix
- success is defined only as a testcase result equal to `"succeeded"`

The pinned official runner ref used by this repo models `goodput` and
`crosstraffic` differently:

- they are **measurements**, not ordinary testcases
- they still launch the implementation with runtime testcase name `transfer`
- their per-pair outcome is written to the runner JSON `measurements` matrix,
  not the `results` matrix

This means the endpoint behavior in `coquic` is already sufficient for the
current pinned runner contract. The missing support is in repo-owned workflow
and wrapper logic.

## Scope

This design covers:

- `.github/workflows/interop.yml`
- `tests/nix/interop_runner_test.sh`
- workflow/contract tests that pin the expected interop request and wrapper
  behavior

## Non-Goals

- changing `coquic` runtime parsing to accept `TESTCASE=goodput`
- changing `coquic` runtime parsing to accept `TESTCASE=crosstraffic`
- altering HTTP/0.9 endpoint behavior for these cases
- implementing any local TCP cross-traffic generator
- interpreting or enforcing the numeric goodput values ourselves
- changing pinned runner refs, simulator refs, or container defaults

## Decisions

### 1. Support Measurements Only In The Official-Runner Path

The repo will support `goodput` and `crosstraffic` only in the official-runner
workflow/wrapper path.

`coquic` runtime testcase parsing remains unchanged.

Rationale:

- the pinned runner already maps these measurement names to runtime testcase
  `transfer`
- no runtime alias is required for current official interop
- keeping runtime unchanged avoids adding behavior that is not exercised by the
  current contract

### 2. Extend The Workflow Testcase List

The GitHub workflow will request:

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

This preserves the current smoke and loss coverage while adding the two new
measurement cases.

### 3. Make The Wrapper Measurement-Aware

The wrapper must distinguish between:

- testcase outcomes from runner JSON `results`
- measurement outcomes from runner JSON `measurements`

For each requested name:

- if it appears in the per-pair testcase `results` entry, require
  `result == "succeeded"`
- else if it appears in the per-pair `measurements` entry, require
  `result == "succeeded"`
- else fail with a clear "missing requested testcase metadata" style error

The wrapper should not attempt to interpret measurement `details` values beyond
recording that the runner marked the measurement as succeeded.

### 4. Keep Log Verification Uniform

The existing per-requested-name log directory check remains in place:

- `${direction_log_dir}/${server}_${client}/${requested_name}`

This should continue to work for both ordinary testcases and measurements,
because the official runner writes logs under the measurement name for
measurement runs.

### 5. Pin The Measurement-Aware Contract In Repo Tests

The repo tests that guard interop wrapper behavior must be updated so this
support does not regress silently.

Required coverage:

- workflow test pins the expanded `INTEROP_TESTCASES` string
- wrapper contract test pins the presence of measurement-aware JSON handling
- wrapper contract test still forbids old deprecated image-selection branches

## Architecture

### Workflow Layer

`interop.yml` remains a single-job workflow that invokes the local wrapper.

The only workflow-level change is the requested testcase string.

### Wrapper Layer

`tests/nix/interop_runner_test.sh` remains the sole repo-owned adapter between
GitHub/Nix execution and the pinned official runner.

Its validation logic becomes:

1. run the official runner and require `results.json`
2. verify single client/server pair shape as today
3. build a name-to-status map from `results[0]`
4. build a name-to-status map from `measurements[0]`
5. for each requested name:
   - validate it from testcase results if present there
   - otherwise validate it from measurement results if present there
   - otherwise fail as unsupported/missing
6. verify log directory existence for every requested name

### Runtime Layer

No runtime-layer change is part of this design.

The existing behavior remains:

- official runner launches `goodput` and `crosstraffic` with
  `TESTCASE_CLIENT=transfer` and `TESTCASE_SERVER=transfer`
- `coquic` continues to parse and execute `transfer`
- the network scenario and extra competing TCP containers remain the official
  runner's responsibility

## Error Handling

The wrapper should keep failing fast with explicit messages when:

- the runner JSON file is missing
- the runner JSON shape does not match one client/server pair
- a requested name is absent from both testcase results and measurements
- a requested testcase result is not `"succeeded"`
- a requested measurement result is not `"succeeded"`
- the expected per-name log directory is missing

The failure wording should stay concrete enough that CI logs identify whether
the problem is:

- workflow request drift
- wrapper parsing drift
- runner JSON contract drift
- genuine testcase/measurement failure

## Testing

### Repo Tests

Update:

- `tests/nix/github_interop_workflow_test.sh`
- `tests/nix/official_interop_runner_contract_test.sh`

No runtime parser tests are needed, because this design intentionally makes no
runtime testcase additions.

### Verification

Minimum verification for implementation:

- run the workflow contract test
- run the official interop wrapper contract test
- run the main test suite if implementation touches shared code or contract
  helpers used elsewhere

## Risks

### 1. Runner JSON Drift

The wrapper currently depends on a specific JSON shape from the pinned runner.
Measurement support adds one more shape dependency: `measurements[0]`.

Mitigation:

- keep the parsing logic narrow and explicit
- pin the measurement-aware fragments in the wrapper contract test

### 2. False Assumption About Measurement Success Encoding

If a future runner revision changes how measurement status is encoded, the
wrapper may reject otherwise valid runs.

Mitigation:

- scope this design to the currently pinned runner ref
- fail explicitly when a requested measurement is missing or not marked
  `"succeeded"`

### 3. Overreaching Runtime Changes

Adding local runtime aliases for `goodput` and `crosstraffic` would broaden the
surface without serving the current interop contract.

Mitigation:

- keep runtime unchanged in this slice
- add alias support only if a future runner contract requires it

## Implementation Outline

1. Extend `INTEROP_TESTCASES` in the workflow.
2. Update wrapper JSON validation to read both testcase and measurement
   sections.
3. Update workflow and wrapper contract tests.
4. Verify the repo tests that pin interop behavior.
