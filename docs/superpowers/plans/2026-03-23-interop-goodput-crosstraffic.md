# Interop Goodput And CrossTraffic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add official-runner support for `goodput` and `crosstraffic` in the GitHub interop workflow and repo-local runner wrapper without changing `coquic` runtime testcase parsing.

**Architecture:** Keep the QUIC HTTP/0.9 runtime unchanged, because the pinned official runner already maps both measurement names to runtime testcase `transfer`. Extend the workflow testcase list and make the wrapper's embedded JSON validation logic distinguish between testcase results in `results[]` and measurement results in `measurements[]`, while preserving the existing per-name log directory checks.

**Tech Stack:** GitHub Actions YAML, Bash, embedded Python, Nix, Docker

---

## File Map

- `.github/workflows/interop.yml`
  Responsibility: request the official runner testcase / measurement names from CI.
- `tests/nix/github_interop_workflow_test.sh`
  Responsibility: pin the workflow contract, including the exact requested testcase string.
- `tests/nix/interop_runner_test.sh`
  Responsibility: run the pinned official runner and validate `results.json` plus per-name log directories.
- `tests/nix/official_interop_runner_contract_test.sh`
  Responsibility: pin the wrapper behavior so measurement-aware validation does not regress silently.

### Task 1: Extend The Workflow Request List First

**Files:**
- Modify: `.github/workflows/interop.yml`
- Modify: `tests/nix/github_interop_workflow_test.sh`

- [ ] **Step 1: Write the failing workflow contract test**

Update `tests/nix/github_interop_workflow_test.sh` so the required workflow fragment expects:

```text
INTEROP_TESTCASES: handshake,handshakeloss,transfer,transferloss,handshakecorruption,transfercorruption,chacha20,longrtt,goodput,crosstraffic
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nix/github_interop_workflow_test.sh`
Expected: FAIL because `.github/workflows/interop.yml` still omits `goodput,crosstraffic`.

- [ ] **Step 3: Write minimal implementation**

Update `.github/workflows/interop.yml` to append `goodput,crosstraffic` to `INTEROP_TESTCASES` and leave the rest of the job structure unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nix/github_interop_workflow_test.sh`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/interop.yml tests/nix/github_interop_workflow_test.sh
git commit -m "ci: request goodput and crosstraffic interop cases"
```

### Task 2: Make The Official Runner Wrapper Measurement-Aware

**Files:**
- Modify: `tests/nix/interop_runner_test.sh`
- Modify: `tests/nix/official_interop_runner_contract_test.sh`

- [ ] **Step 1: Write the failing wrapper contract test**

Extend `tests/nix/official_interop_runner_contract_test.sh` so it requires measurement-aware fragments in `tests/nix/interop_runner_test.sh`, for example:

```text
'measurements = data.get("measurements", [])'
'measurement_results = {'
'if test in testcase_results:'
'elif test in measurement_results:'
```

Keep the existing forbidden fragments that reject the old BoringSSL image switching logic.

- [ ] **Step 2: Run test to verify it fails**

Run: `bash tests/nix/official_interop_runner_contract_test.sh`
Expected: FAIL because `tests/nix/interop_runner_test.sh` still only validates `results[0]`.

- [ ] **Step 3: Write minimal implementation**

Update the embedded Python block in `tests/nix/interop_runner_test.sh` so it:

```python
testcase_results = {
    entry.get("name"): entry.get("result")
    for entry in results[0]
}
measurements = data.get("measurements", [])
measurement_results = {
    entry.get("name"): entry.get("result")
    for entry in (measurements[0] if measurements else [])
}
missing = [
    test for test in requested_tests
    if test not in testcase_results and test not in measurement_results
]
failed = []
for test in requested_tests:
    if test in testcase_results:
        result = testcase_results.get(test)
    else:
        result = measurement_results.get(test)
    if result != "succeeded":
        failed.append(f"{test}={result!r}")
```

Keep the existing:

- single-pair shape checks
- `results.json` existence check
- per-requested-name log directory check under `${direction_log_dir}/${server}_${client}/${testcase}`

- [ ] **Step 4: Run test to verify it passes**

Run: `bash tests/nix/official_interop_runner_contract_test.sh`
Expected: PASS.

- [ ] **Step 5: Re-run the workflow contract test**

Run: `bash tests/nix/github_interop_workflow_test.sh`
Expected: PASS, proving the workflow and wrapper contract tests agree on the expanded request list.

- [ ] **Step 6: Commit**

```bash
git add tests/nix/interop_runner_test.sh tests/nix/official_interop_runner_contract_test.sh
git commit -m "tests: validate interop measurements in runner wrapper"
```

### Task 3: Verify The New Measurement Slice End To End

**Files:**
- Verify: `.github/workflows/interop.yml`
- Verify: `tests/nix/github_interop_workflow_test.sh`
- Verify: `tests/nix/interop_runner_test.sh`
- Verify: `tests/nix/official_interop_runner_contract_test.sh`

- [ ] **Step 1: Run the lightweight repo contract checks**

Run:

```bash
bash tests/nix/github_interop_workflow_test.sh
bash tests/nix/official_interop_runner_contract_test.sh
```

Expected: both PASS.

- [ ] **Step 2: Run the official-runner measurement smoke**

Run:

```bash
INTEROP_TESTCASES=goodput,crosstraffic nix develop -c bash tests/nix/interop_runner_test.sh
```

Expected:

- the pinned official runner completes both directions
- the wrapper accepts both requested names from `measurements[]`
- per-name log directories exist for `goodput` and `crosstraffic`

- [ ] **Step 3: Check the worktree**

Run: `git status --short`
Expected: no unexpected modifications.

- [ ] **Step 4: Review the final diff**

Run:

```bash
git diff -- .github/workflows/interop.yml \
  tests/nix/github_interop_workflow_test.sh \
  tests/nix/interop_runner_test.sh \
  tests/nix/official_interop_runner_contract_test.sh
```

Expected: only workflow request expansion plus measurement-aware wrapper validation changes.
