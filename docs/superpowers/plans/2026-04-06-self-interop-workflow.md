# Self Interop Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one self-interop GitHub Actions job that runs the full official testcase set exactly once with `coquic` as both implementations.

**Architecture:** Add a small repo-local workflow validation script under `tests/nix` that parses `.github/workflows/interop.yml` with PyYAML and asserts the exact `interop-self` contract. Use that script as the failing test, then add one additive job to the workflow that reuses the existing official-runner step structure, points the peer implementation back at `coquic`, and forces a single execution through `INTEROP_DIRECTIONS=coquic-server`.

**Tech Stack:** GitHub Actions YAML, Bash, Python 3 with PyYAML, Nix, `actionlint`

---

## File Map

- Create: `tests/nix/github_interop_workflow_test.sh`
- Modify: `.github/workflows/interop.yml`
- Verify: `docs/superpowers/specs/2026-04-06-self-interop-workflow-design.md`

### Task 1: Add the self-interop workflow job with test-first validation

**Files:**
- Create: `tests/nix/github_interop_workflow_test.sh`
- Modify: `.github/workflows/interop.yml`

- [ ] **Step 1: Write the failing workflow-structure test**

Create `tests/nix/github_interop_workflow_test.sh` with this content:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
import pathlib
import yaml

workflow_path = pathlib.Path(".github/workflows/interop.yml")
workflow = yaml.safe_load(workflow_path.read_text())
jobs = workflow.get("jobs", {})
self_job = jobs.get("interop-self")

if self_job is None:
    raise SystemExit("missing job: interop-self")

if self_job.get("name") != "Self Official Runner":
    raise SystemExit(f"unexpected interop-self name: {self_job.get('name')!r}")

if self_job.get("timeout-minutes") != 90:
    raise SystemExit(
        f"unexpected interop-self timeout: {self_job.get('timeout-minutes')!r}"
    )

steps = self_job.get("steps", [])
run_step = next(
    (step for step in steps if step.get("name") == "Run Official self Interop Tests"),
    None,
)
if run_step is None:
    raise SystemExit("missing self interop run step")

expected_testcases = (
    "handshake,handshakeloss,transfer,keyupdate,transferloss,"
    "handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,"
    "goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,"
    "amplificationlimit,rebind-port,rebind-addr,connectionmigration"
)
expected_env = {
    "INTEROP_TESTCASES": expected_testcases,
    "INTEROP_PEER_IMPL": "coquic",
    "INTEROP_PEER_IMAGE": "coquic-interop:quictls-musl",
    "INTEROP_DIRECTIONS": "coquic-server",
}

run_env = run_step.get("env", {})
for key, expected_value in expected_env.items():
    actual_value = run_env.get(key)
    if actual_value != expected_value:
        raise SystemExit(f"unexpected {key}: {actual_value!r}")

if run_step.get("run") != "nix develop -c bash interop/run-official.sh":
    raise SystemExit(f"unexpected self interop run command: {run_step.get('run')!r}")

artifact_step = next(
    (
        step
        for step in steps
        if step.get("uses") == "actions/upload-artifact@v4"
    ),
    None,
)
if artifact_step is None:
    raise SystemExit("missing self interop artifact upload step")

artifact_with = artifact_step.get("with", {})
if artifact_with.get("name") != "interop-logs-self":
    raise SystemExit(f"unexpected self interop artifact name: {artifact_with.get('name')!r}")
if artifact_with.get("path") != ".interop-logs/official":
    raise SystemExit(f"unexpected self interop artifact path: {artifact_with.get('path')!r}")

print("interop-self workflow contract looks correct")
PY
```

- [ ] **Step 2: Run the workflow test first and verify it fails for the missing job**

Run:

```bash
bash tests/nix/github_interop_workflow_test.sh
```

Expected: FAIL with `missing job: interop-self`.

- [ ] **Step 3: Add the new `interop-self` job to the workflow**

Append this job to `.github/workflows/interop.yml` after the existing peer jobs:

```yaml
  interop-self:
    name: Self Official Runner
    runs-on: ubuntu-latest
    timeout-minutes: 90

    steps:
      - name: Checkout
        uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Nix
        uses: DeterminateSystems/nix-installer-action@main

      - name: Enable Magic Nix Cache
        uses: DeterminateSystems/magic-nix-cache-action@main

      - name: Set up Docker 29.1
        uses: docker/setup-docker-action@v5
        with:
          version: v29.1.5

      - name: Show Docker Version
        run: |
          docker version
          docker compose version

      - name: Run Official self Interop Tests
        env:
          INTEROP_TESTCASES: handshake,handshakeloss,transfer,keyupdate,transferloss,handshakecorruption,transfercorruption,blackhole,chacha20,longrtt,goodput,crosstraffic,ipv6,multiplexing,retry,resumption,zerortt,v2,amplificationlimit,rebind-port,rebind-addr,connectionmigration
          INTEROP_PEER_IMPL: coquic
          INTEROP_PEER_IMAGE: coquic-interop:quictls-musl
          INTEROP_DIRECTIONS: coquic-server
        run: nix develop -c bash interop/run-official.sh

      - name: Upload Interop Logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: interop-logs-self
          path: .interop-logs/official
          if-no-files-found: warn
```

- [ ] **Step 4: Run the workflow contract test and workflow lint on the edited YAML**

Run:

```bash
bash tests/nix/github_interop_workflow_test.sh
nix shell nixpkgs#actionlint -c actionlint .github/workflows/interop.yml
```

Expected:
- the shell test prints `interop-self workflow contract looks correct`
- `actionlint` exits successfully with no output

- [ ] **Step 5: Commit the workflow change and validation script**

Run:

```bash
git add .github/workflows/interop.yml tests/nix/github_interop_workflow_test.sh
git commit -m "ci: add self interop workflow job"
```

Expected: one clean commit that adds the workflow job and its validation script only.
