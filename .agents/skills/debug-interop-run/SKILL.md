---
name: debug-interop-run
description: Debug failed remote GitHub Actions Interop workflow runs for the coquic repository. Use when given a .github/workflows/interop.yml run URL or run ID and asked to inspect CI, download failed interop logs/artifacts with gh, identify failed peer/testcase/direction combinations, reproduce them locally with interop/run-official.sh, fix reproducible coquic bugs, validate, commit, push, and dispatch a fresh Interop workflow run.
---

# Debug Interop Run

Use this workflow for remote failures from `.github/workflows/interop.yml`, such as
`https://github.com/minhuw/coquic/actions/runs/<run-id>`.

## Ground Rules

- Use `gh` for GitHub Actions inspection.
- Use `-R <owner>/<repo>` whenever the URL points outside the current remote.
- Store downloaded CI material under `.remote-ci/` using repository naming conventions.
- Do not commit `.remote-ci/`, `.interop-logs/`, build outputs, or other generated state.
- Use `nix develop -c ...` for build, test, format, lint, and local reproduction commands.
- Prefer fixing only failures that reproduce locally. Report non-reproducible remote-only failures separately.
- Before editing, inspect the dirty tree and preserve unrelated user changes.
- After fixes, validate with focused reproduction, then the relevant local tests, then `nix develop -c zig build test` unless there is a clear constraint.
- Commit with Conventional Commits, push to `origin`, and trigger `.github/workflows/interop.yml` manually only after validation passes.

## 1. Capture The Run

Parse the run URL:

```bash
run_id=<id from /actions/runs/<id>>
repo=<owner>/<repo from URL>
mkdir -p ".remote-ci/${run_id}"
```

Inspect run and job state:

```bash
gh run view "${run_id}" -R "${repo}" \
  --json status,conclusion,event,headSha,headBranch,url,jobs \
  > ".remote-ci/${run_id}/run.json"

gh run view "${run_id}" -R "${repo}" --log-failed \
  > ".remote-ci/${run_id}-failed.log"
```

If the run is still in progress, say so and inspect only completed failed jobs. If no job has
failed yet, stop before downloading artifacts.

For each failed job ID, save a focused failed-job log:

```bash
gh run view --job "<job-id>" -R "${repo}" --log-failed \
  > ".remote-ci/${run_id}-job-<job-id>-failed.log"
```

## 2. Download Interop Artifacts

Download artifacts into the run directory:

```bash
mkdir -p ".remote-ci/${run_id}/artifacts"
gh run download "${run_id}" -R "${repo}" \
  --dir ".remote-ci/${run_id}/artifacts"
```

Relevant artifact names:

- `interop-logs-<peer>`: full official runner logs under `.interop-logs/official`.
- `interop-results-<peer>`: JSON result snapshot for that matrix job.
- `interop-results-self`: self-run result snapshot.

Use `find` and `rg` to locate:

```bash
find ".remote-ci/${run_id}/artifacts" -maxdepth 4 -type f | sort
rg -n '"result": "failed"|"result":"failed"|failed|error|timed out|Traceback' \
  ".remote-ci/${run_id}/artifacts"
```

## 3. Identify Failed Cases

For each failed job, derive:

- peer implementation, for example `quic-go`, `picoquic`, `quinn`, `msquic`, `quiche`,
  `ngtcp2`, `neqo`, `mvfst`, `aioquic`, `xquic`, `s2n-quic`, or `coquic`.
- direction:
  - `coquic-server` when result path is `coquic_<peer>/results.json`.
  - `coquic-client` when result path is `<peer>_coquic/results.json`.
  - `both` only when reproducing both directions is necessary.
- failed testcase names from `results.json`, including measurements such as `goodput` or
  `crosstraffic` if those failed.
- peer image and `impl` from `.github/workflows/interop.yml`.
- congestion-control value if the matrix or logs set `COQUIC_CONGESTION_CONTROL`.

Prefer the artifact `results.json` over prose logs for the failure list. Use logs and qlog/pcap
files to explain why a testcase failed.

## 4. Reproduce Locally

Reproduce one peer/direction/testcase group at a time. Use the same official runner entrypoint as
CI, but narrow `INTEROP_TESTCASES`.

Example for a peer matrix job:

```bash
rm -rf .interop-logs/official
nix develop -c env \
  INTEROP_TESTCASES='<comma-separated-failed-testcases>' \
  INTEROP_COQUIC_SERVER_TESTCASES='<same list if coquic-server is involved>' \
  INTEROP_COQUIC_CLIENT_TESTCASES='<same list if coquic-client is involved>' \
  INTEROP_PEER_IMPL='<impl from workflow>' \
  INTEROP_PEER_IMAGE='<image from workflow>' \
  INTEROP_DIRECTIONS='<coquic-server|coquic-client|both>' \
  COQUIC_CONGESTION_CONTROL='<value or empty>' \
  COQUIC_RUNTIME_TRACE=1 \
  COQUIC_PACKET_TRACE=1 \
  bash interop/run-official.sh
```

Example for the self job:

```bash
rm -rf .interop-logs/official
nix develop -c env \
  INTEROP_TESTCASES='<comma-separated-failed-testcases>' \
  INTEROP_PEER_IMPL='coquic' \
  INTEROP_PEER_IMAGE='coquic-interop:quictls-musl' \
  INTEROP_DIRECTIONS='coquic-server' \
  COQUIC_RUNTIME_TRACE=1 \
  COQUIC_PACKET_TRACE=1 \
  bash interop/run-official.sh
```

If reproduction needs analysis tooling, rely on the script's Nix fallback or enter a shell with
the needed package. Keep generated `.interop-logs/` out of git.

## 5. Diagnose

Start from the narrowed local logs:

```bash
find .interop-logs/official -type f | sort
rg -n 'failed|error|timeout|close|transport|packet|trace|qlog|result' .interop-logs/official
```

Inspect qlog, pcap, stdout/stderr, runner output, failed run logs, failed job logs, and result JSON
for the failing testcase. Compare remote artifacts under `.remote-ci/<run-id>/artifacts` with local
`.interop-logs/official`.

When the issue is QUIC protocol behavior, use the repo's QUIC RAG skill/query flow before making
protocol claims. Ground conclusions in RFC citations when useful.

## 6. Fix And Validate

For each reproducible failure:

1. Add or update focused unit/runtime tests that fail before the fix when practical.
2. Make the smallest source change that addresses the reproduced cause.
3. Run the focused test or reproduction command.
4. Rerun the narrowed `interop/run-official.sh` command for the affected peer/testcase/direction.
5. Repeat until all locally reproducible failed cases pass.

Then run broader validation:

```bash
nix develop -c zig build test
git diff --check
```

If full validation is blocked by time or environment, state the exact constraint and run the
closest focused validation instead.

## 7. Commit, Push, And Redispatch

Before committing:

```bash
git status --short
git diff --stat
```

Stage only source/test/docs changes that should be tracked. Do not stage `.remote-ci/`,
`.interop-logs/`, `.rag/`, `.zig-cache/`, or downloaded/generated state.

Commit and push:

```bash
git commit -m 'fix: <concise interop failure summary>'
git push origin HEAD
```

Trigger a fresh Interop run:

```bash
gh workflow run .github/workflows/interop.yml --ref main
gh run list --workflow .github/workflows/interop.yml --branch main --limit 5 \
  --json databaseId,displayTitle,event,headSha,status,conclusion,url,createdAt
```

Report the original workflow, run ID, job, failing step, relevant log excerpt, local reproduction
commands, validation commands, new commit, and new Interop run ID/URL/head SHA. Also report which
remote failed cases were fixed and any failed cases that were not reproducible locally.
