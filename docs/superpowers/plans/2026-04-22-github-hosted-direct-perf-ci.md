# GitHub Hosted Direct Perf CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Docker-based `perf.yml` benchmark path with direct hosted-runner execution of `coquic-perf` while preserving the existing advisory workflow, benchmark tuples, and artifact manifest flow.

**Architecture:** Keep `.github/workflows/perf.yml` as thin orchestration and keep `bench/run-host-matrix.sh` as the repo-owned entry point, but rewrite that harness to build one optimized `coquic-perf` binary through Nix and launch pinned server/client processes directly with `taskset`. Preserve the per-run `.json` and `.txt` outputs plus `manifest.json`, add a lightweight `environment.txt` artifact, and make the summary renderer describe the direct build target instead of a Docker image.

**Tech Stack:** Bash, Python 3, Nix, Zig build artifacts, GitHub Actions, Linux `taskset`

---

## File Structure

- Modify: `scripts/render-perf-summary.py`
  - Change the summary metadata line from Docker-image terminology to direct-build-target terminology while remaining backward-compatible with older manifests.
- Modify: `tests/fixtures/perf/smoke-manifest.json`
  - Update the fixture manifest metadata field used by the summary renderer regression test.
- Modify: `tests/nix/perf_summary_render_test.sh`
  - Assert the new summary metadata line and keep the rest of the summary contract green.
- Modify: `bench/run-host-matrix.sh`
  - Replace Docker orchestration with direct hosted-runner process orchestration, emit `environment.txt`, build one optimized `coquic-perf`, and preserve manifest generation.
- Modify: `tests/nix/perf_harness_test.sh`
  - Replace Docker-specific static contract checks with direct-host harness checks.
- Modify: `docs/quic-perf.md`
  - Document direct-host matrix execution, new environment overrides, and the environment snapshot artifact.
- Verify: `tests/nix/github_perf_workflow_test.sh`
  - Confirm the existing workflow contract stays valid with the unchanged workflow entry point.

### Task 1: Rename Summary Metadata From Image To Target

**Files:**
- Modify: `scripts/render-perf-summary.py`
- Modify: `tests/fixtures/perf/smoke-manifest.json`
- Modify: `tests/nix/perf_summary_render_test.sh`

- [ ] **Step 1: Update the summary fixture and regression test to expect a direct build target**

```json
{
  "preset": "smoke",
  "build_target": "coquic-perf-quictls-musl",
  "results_root": "/tmp/.bench-results",
  "runs": [
    {
      "schema_version": 1,
      "status": "ok",
      "mode": "bulk",
      "direction": "download",
      "backend": "socket",
      "elapsed_ms": 42,
      "throughput_mib_per_s": 1.234,
      "requests_per_s": 0.0,
      "latency": {
        "p50_us": 0,
        "p99_us": 0
      },
      "result_file": "smoke-socket-bulk-s1-c1-q1.json",
      "summary_file": "smoke-socket-bulk-s1-c1-q1.txt"
    }
  ]
}
```

```bash
# tests/nix/perf_summary_render_test.sh
grep -F 'Target: `coquic-perf-quictls-musl`' "${output}" >/dev/null || {
  echo 'missing target line' >&2
  exit 1
}

if grep -F 'Image:' "${output}" >/dev/null; then
  echo 'unexpected image line in direct-host summary' >&2
  exit 1
fi

printf '%s\n' \
'{' \
'  "preset": "smoke",' \
'  "build_target": "coquic-perf-quictls-musl",' \
'  "runs": []' \
'}' > "${empty_manifest}"
```

- [ ] **Step 2: Run the summary regression test to verify it fails on the old renderer**

Run: `bash tests/nix/perf_summary_render_test.sh`

Expected: FAIL with `missing target line` because `render-perf-summary.py` still prints `Image:` and only reads `image_tag`.

- [ ] **Step 3: Implement backward-compatible target rendering in the summary script**

```python
# scripts/render-perf-summary.py

def main() -> int:
    args = parse_args()
    try:
        manifest = load_manifest(Path(args.manifest))
        runs = manifest.get("runs", [])
        if not isinstance(runs, list):
            raise ValueError("manifest field `runs` must be a list")

        target = manifest.get("build_target")
        if target is None:
            target = manifest.get("image_tag", "unknown")

        print("## Advisory QUIC Perf")
        print()
        print(f"Event: `{args.event_name}`")
        print(f"Commit: `{args.commit}`")
        print(f"Preset: `{manifest.get('preset', 'unknown')}`")
        print(f"Target: `{target}`")
        print()
        print("Benchmark data from GitHub-hosted runners is advisory and may vary between runs.")
        print()
```

Keep the rest of the file unchanged so older manifests that still contain `image_tag` continue to render successfully.

- [ ] **Step 4: Run the summary regression test to verify it passes**

Run: `bash tests/nix/perf_summary_render_test.sh`

Expected: PASS with `perf summary renderer looks correct`.

- [ ] **Step 5: Commit**

```bash
git add scripts/render-perf-summary.py \
  tests/fixtures/perf/smoke-manifest.json \
  tests/nix/perf_summary_render_test.sh
git commit -m "perf: describe direct benchmark target in summaries"
```

### Task 2: Replace The Docker Harness With Direct Hosted-Runner Execution

**Files:**
- Modify: `bench/run-host-matrix.sh`
- Modify: `tests/nix/perf_harness_test.sh`

- [ ] **Step 1: Rewrite the harness contract test to describe the direct-host runner**

```bash
# tests/nix/perf_harness_test.sh
grep -F -- 'PERF_BINARY_ATTR' "${script}" >/dev/null || {
  echo 'missing binary attr override in harness script' >&2
  exit 1
}

grep -F -- 'coquic-perf-quictls-musl' "${script}" >/dev/null || {
  echo 'missing direct perf binary default in harness script' >&2
  exit 1
}

grep -F -- 'taskset -c "${server_cpus}"' "${script}" >/dev/null || {
  echo 'missing server CPU pinning in harness script' >&2
  exit 1
}

grep -F -- 'taskset -c "${client_cpus}"' "${script}" >/dev/null || {
  echo 'missing client CPU pinning in harness script' >&2
  exit 1
}

grep -F -- 'tests/fixtures/quic-server-cert.pem' "${script}" >/dev/null || {
  echo 'missing server certificate path in harness script' >&2
  exit 1
}

grep -F -- 'tests/fixtures/quic-server-key.pem' "${script}" >/dev/null || {
  echo 'missing server key path in harness script' >&2
  exit 1
}

grep -F -- 'environment.txt' "${script}" >/dev/null || {
  echo 'missing environment snapshot in harness script' >&2
  exit 1
}

if grep -F -- 'docker ' "${script}" >/dev/null; then
  echo 'unexpected docker usage in direct harness script' >&2
  exit 1
fi

if grep -F -- '--network host' "${script}" >/dev/null; then
  echo 'unexpected host-network docker flag in direct harness script' >&2
  exit 1
fi

if grep -F -- '--cap-add IPC_LOCK' "${script}" >/dev/null; then
  echo 'unexpected container capability override in direct harness script' >&2
  exit 1
fi

grep -F -- 'coquic-perf-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing direct perf package export in flake.nix' >&2
  exit 1
}
```

Keep the existing preset tuple checks and `.bench-results/` ignore check unchanged.

- [ ] **Step 2: Run the harness contract test to verify it fails before the script rewrite**

Run: `bash tests/nix/perf_harness_test.sh`

Expected: FAIL with `missing binary attr override in harness script` or another new direct-host assertion because `bench/run-host-matrix.sh` still contains Docker-specific code.

- [ ] **Step 3: Replace `bench/run-host-matrix.sh` with a direct-host harness**

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
default_manifest_path="${repo_root}/.bench-results/manifest.json"
results_root="${PERF_RESULTS_ROOT:-$(dirname "${default_manifest_path}")}"
manifest_path="${results_root}/manifest.json"
environment_path="${results_root}/environment.txt"
binary_attr="${PERF_BINARY_ATTR:-coquic-perf-quictls-musl}"
build_target="${PERF_BUILD_TARGET:-${binary_attr}}"
server_cpus="${PERF_SERVER_CPUS:-2}"
client_cpus="${PERF_CLIENT_CPUS:-3}"
port="${PERF_PORT:-9443}"
preset="smoke"
perf_bin=''
server_pid=''

usage() {
  cat <<'USAGE'
usage: bash bench/run-host-matrix.sh [--preset smoke|ci]

environment overrides:
  PERF_RESULTS_ROOT  result directory (default: .bench-results)
  PERF_BINARY_ATTR   nix package attr to build (default: coquic-perf-quictls-musl)
  PERF_BUILD_TARGET  manifest label for summary output (default: PERF_BINARY_ATTR)
  PERF_SERVER_CPUS   CPU set for server process (default: 2)
  PERF_CLIENT_CPUS   CPU set for client process (default: 3)
  PERF_PORT          UDP port for server/client (default: 9443)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --preset)
      [ $# -ge 2 ] || {
        echo 'missing value for --preset' >&2
        exit 1
      }
      preset="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "${preset}" in
  smoke)
    runs=(
      "socket bulk download 65536 0 0 1 1 1 0ms 5s"
      "socket rr stay 32 48 32 1 1 4 0ms 5s"
      "socket crr stay 24 24 8 1 2 1 0ms 5s"
    )
    ;;
  ci)
    runs=(
      "socket bulk download 0 1048576 none 4 1 1 5s 60s"
      "socket rr stay 32 32 none 1 256 16 5s 45s"
      "socket crr stay 32 32 none 1 512 1 5s 45s"
    )
    ;;
  *)
    echo "unsupported preset: ${preset}" >&2
    exit 1
    ;;
esac

mkdir -p "${results_root}"
rm -f "${results_root}"/*.json "${results_root}"/*.txt "${results_root}"/*.log "${environment_path}"

stop_server() {
  if [ -n "${server_pid}" ]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=''
  fi
}

cleanup() {
  stop_server
}
trap cleanup EXIT INT TERM

command -v taskset >/dev/null || {
  echo 'taskset is required for bench/run-host-matrix.sh' >&2
  exit 1
}

binary_path="$(nix build --print-out-paths ".#${binary_attr}")"
perf_bin="${binary_path}/bin/coquic-perf"
[ -x "${perf_bin}" ] || {
  echo "missing perf binary: ${perf_bin}" >&2
  exit 1
}

{
  echo "build_target=${build_target}"
  echo "binary_attr=${binary_attr}"
  echo "server_cpus=${server_cpus}"
  echo "client_cpus=${client_cpus}"
  echo "port=${port}"
  echo
  uname -a
  echo
  lscpu
  echo
  nproc
} > "${environment_path}"

for run in "${runs[@]}"; do
  read -r backend mode direction request_bytes response_bytes limit streams connections inflight warmup duration <<<"${run}"
  run_name="${preset}-${backend}-${mode}-s${streams}-c${connections}-q${inflight}"
  json_path="${results_root}/${run_name}.json"
  txt_path="${results_root}/${run_name}.txt"
  server_log_path="${results_root}/${run_name}.server.log"

  stop_server
  taskset -c "${server_cpus}" "${perf_bin}" server \
    --host 127.0.0.1 \
    --port "${port}" \
    --certificate-chain "${repo_root}/tests/fixtures/quic-server-cert.pem" \
    --private-key "${repo_root}/tests/fixtures/quic-server-key.pem" \
    --io-backend "${backend}" >"${server_log_path}" 2>&1 &
  server_pid="$!"

  sleep 1

  client_args=(
    client
    --host 127.0.0.1
    --port "${port}"
    --mode "${mode}"
    --io-backend "${backend}"
    --request-bytes "${request_bytes}"
    --response-bytes "${response_bytes}"
    --streams "${streams}"
    --connections "${connections}"
    --requests-in-flight "${inflight}"
    --warmup "${warmup}"
    --duration "${duration}"
    --json-out "${json_path}"
  )

  if [ "${mode}" = 'bulk' ]; then
    client_args+=(--direction "${direction}")
    if [ "${limit}" != 'none' ]; then
      client_args+=(--total-bytes "${limit}")
    fi
  elif [ "${limit}" != 'none' ]; then
    client_args+=(--requests "${limit}")
  fi

  taskset -c "${client_cpus}" "${perf_bin}" "${client_args[@]}" | tee "${txt_path}"

  stop_server
  [ -f "${json_path}" ] || {
    echo "missing JSON result: ${json_path}" >&2
    exit 1
  }
done

python3 - <<'PY' "${results_root}" "${manifest_path}" "${preset}" "${build_target}"
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
preset = sys.argv[3]
build_target = sys.argv[4]

runs = []
for path in sorted(root.glob('*.json')):
    if path.name == manifest_path.name:
        continue
    record = json.loads(path.read_text())
    record['result_file'] = path.name
    txt_path = path.with_suffix('.txt')
    if txt_path.exists():
        record['summary_file'] = txt_path.name
    runs.append(record)

manifest = {
    'preset': preset,
    'build_target': build_target,
    'results_root': str(root),
    'runs': runs,
}
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
PY

echo "wrote manifest to ${manifest_path}"
```

Do not change the benchmark tuples. Keep `socket` as the only backend in both presets.

- [ ] **Step 4: Run the static harness contract test to verify it passes**

Run: `bash tests/nix/perf_harness_test.sh`

Expected: PASS with `perf harness contract looks correct`.

- [ ] **Step 5: Run the direct-host smoke preset locally to verify real execution**

Run: `PERF_RESULTS_ROOT=/tmp/coquic-direct-smoke bash bench/run-host-matrix.sh --preset smoke`

Expected:
- three `status=ok` summary lines, one each for `bulk`, `rr`, and `crr`
- `/tmp/coquic-direct-smoke/manifest.json` exists
- `/tmp/coquic-direct-smoke/environment.txt` exists
- per-run `.json`, `.txt`, and `.server.log` files exist under `/tmp/coquic-direct-smoke`

- [ ] **Step 6: Commit**

```bash
git add bench/run-host-matrix.sh tests/nix/perf_harness_test.sh
git commit -m "perf: run hosted benchmarks without docker"
```

### Task 3: Update User-Facing Perf Docs And Re-Run CI Contract Checks

**Files:**
- Modify: `docs/quic-perf.md`
- Verify: `tests/nix/github_perf_workflow_test.sh`
- Verify: `tests/nix/perf_summary_render_test.sh`
- Verify: `tests/nix/perf_harness_test.sh`

- [ ] **Step 1: Update `docs/quic-perf.md` to describe the new direct-host harness**

````markdown
# QUIC Perf Benchmarks

`coquic-perf` exercises the QUIC stack in three modes:

- `bulk` for sustained transfer throughput
- `rr` for established-connection request-response throughput and latency
- `crr` for connection-request-response throughput and latency

The client prints a human-readable summary to stdout and can also write a machine-readable JSON result with `--json-out`.

## Build The Binary

```bash
nix develop -c zig build
./zig-out/bin/coquic-perf server --host 127.0.0.1 --port 9443 \
  --certificate-chain tests/fixtures/quic-server-cert.pem \
  --private-key tests/fixtures/quic-server-key.pem
```

## Run A Direct Local `rr` Client

```bash
./zig-out/bin/coquic-perf client --host 127.0.0.1 --port 9443 --mode rr \
  --request-bytes 32 --response-bytes 48 --requests 1000 --requests-in-flight 4 \
  --json-out rr.json
```

## Run The Direct Host Matrix

```bash
bash bench/run-host-matrix.sh --preset smoke
```

The harness builds one optimized `coquic-perf` binary through Nix, launches the
server and client directly on the host with `taskset -c`, writes per-run text
and JSON files plus `.bench-results/manifest.json`, and records
`.bench-results/environment.txt` with runner details that help interpret noisy
GitHub-hosted measurements.

Useful environment overrides:

- `PERF_RESULTS_ROOT` to choose a different output directory
- `PERF_BINARY_ATTR` to choose a different Nix build attr for `coquic-perf`
- `PERF_BUILD_TARGET` to override the summary label written into `manifest.json`
- `PERF_SERVER_CPUS` and `PERF_CLIENT_CPUS` to pin different cores
- `PERF_PORT` to move the benchmark listener port
````

- [ ] **Step 2: Re-run the contract checks and workflow contract after the docs update**

Run: `bash tests/nix/perf_summary_render_test.sh`
Expected: PASS with `perf summary renderer looks correct`

Run: `bash tests/nix/perf_harness_test.sh`
Expected: PASS with `perf harness contract looks correct`

Run: `bash tests/nix/github_perf_workflow_test.sh`
Expected: PASS with `perf workflow contract looks correct`

- [ ] **Step 3: Commit**

```bash
git add docs/quic-perf.md
git commit -m "docs: describe direct hosted perf harness"
```
