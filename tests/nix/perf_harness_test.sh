#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
script="${repo_root}/bench/run-host-matrix.sh"
flake="${repo_root}/flake.nix"
ignore_file="${repo_root}/.gitignore"

[ -f "${script}" ] || {
  echo "missing harness script: ${script}" >&2
  exit 1
}

grep -F -- 'binary_attr="${PERF_BINARY_ATTR:-coquic-quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing real package attr default in harness script' >&2
  exit 1
}

grep -F -- 'build_target="${PERF_BUILD_TARGET:-coquic-perf-quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing perf build label default in harness script' >&2
  exit 1
}

grep -F -- 'nix build --print-out-paths ".#${binary_attr}"' "${script}" >/dev/null || {
  echo 'missing direct nix build in harness script' >&2
  exit 1
}

grep -F -- 'perf_bin="${binary_path}/bin/coquic-perf"' "${script}" >/dev/null || {
  echo 'missing direct perf binary resolution in harness script' >&2
  exit 1
}

grep -F -- 'handle_signal() {' "${script}" >/dev/null || {
  echo 'missing signal handler in harness script' >&2
  exit 1
}

grep -F -- "trap cleanup EXIT" "${script}" >/dev/null || {
  echo 'missing EXIT cleanup trap in harness script' >&2
  exit 1
}

grep -F -- "trap 'handle_signal INT' INT" "${script}" >/dev/null || {
  echo 'missing INT signal trap in harness script' >&2
  exit 1
}

grep -F -- "trap 'handle_signal TERM' TERM" "${script}" >/dev/null || {
  echo 'missing TERM signal trap in harness script' >&2
  exit 1
}

grep -F -- 'exit 130' "${script}" >/dev/null || {
  echo 'missing INT signal exit code in harness script' >&2
  exit 1
}

grep -F -- 'exit 143' "${script}" >/dev/null || {
  echo 'missing TERM signal exit code in harness script' >&2
  exit 1
}

if grep -F -- 'trap cleanup EXIT INT TERM' "${script}" >/dev/null; then
  echo 'unexpected direct cleanup trap for INT/TERM in harness script' >&2
  exit 1
fi

if grep -F -- 'apps.${system}.${binary_attr}.program' "${script}" >/dev/null; then
  echo 'unexpected app fallback in harness script' >&2
  exit 1
fi

if grep -F -- 'builtins.currentSystem' "${script}" >/dev/null; then
  echo 'unexpected system eval fallback in harness script' >&2
  exit 1
fi

if grep -F -- 'package_attr=' "${script}" >/dev/null; then
  echo 'unexpected package attr rewrite fallback in harness script' >&2
  exit 1
fi

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

grep -F -- 'usage: bash bench/run-host-matrix.sh [--preset smoke|ci]' "${script}" >/dev/null || {
  echo 'missing ci preset in harness usage' >&2
  exit 1
}

grep -F -- 'ci)' "${script}" >/dev/null || {
  echo 'missing ci preset case in harness script' >&2
  exit 1
}

smoke_runs=(
  '"socket bulk download 65536 0 0 1 1 1 0ms 5s"'
  '"socket rr stay 32 48 32 1 1 4 0ms 5s"'
  '"socket crr stay 24 24 8 1 2 1 0ms 5s"'
)

for run in "${smoke_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing smoke run tuple: ${run}" >&2
    exit 1
  }
done

ci_runs=(
  '"socket bulk download 0 1048576 none 4 1 1 5s 60s"'
  '"socket rr stay 32 32 none 1 256 16 5s 45s"'
  '"socket crr stay 32 32 none 1 512 1 5s 45s"'
)

for run in "${ci_runs[@]}"; do
  grep -F -- "${run}" "${script}" >/dev/null || {
    echo "missing ci run tuple: ${run}" >&2
    exit 1
  }
done

if grep -F -- '"io_uring ' "${script}" >/dev/null; then
  echo 'unexpected io_uring run tuple in harness script' >&2
  exit 1
fi

grep -F -- 'coquic-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing direct perf package export in flake.nix' >&2
  exit 1
}

grep -F -- '.bench-results/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark results ignore rule' >&2
  exit 1
}

package_path="$(nix build --no-link --print-out-paths .#coquic-quictls-musl)"
[ -x "${package_path}/bin/coquic-perf" ] || {
  echo 'real direct-build package is missing bin/coquic-perf' >&2
  exit 1
}

if nix build --no-link .#coquic-perf-quictls-musl >/dev/null 2>&1; then
  echo 'unexpected perf app label is buildable as a package attr' >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
fake_bin_dir="${tmp_dir}/fake-bin"
fake_store="${tmp_dir}/fake-store"
results_root="${tmp_dir}/results"
log_path="${tmp_dir}/invocations.log"
mkdir -p "${fake_bin_dir}" "${fake_store}/bin" "${results_root}"

cat > "${fake_store}/bin/coquic-perf" <<'FAKE_PERF'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'coquic-perf\t%s\n' "$*" >>"${log_path}"
mode="$1"
shift
case "${mode}" in
  server)
    echo "fake server started"
    trap 'exit 0' TERM INT
    while :; do
      sleep 1
    done
    ;;
  client)
    json_out=''
    while [ $# -gt 0 ]; do
      case "$1" in
        --json-out)
          json_out="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    [ -n "${json_out}" ] || {
      echo 'missing --json-out in fake client' >&2
      exit 1
    }
    printf '{"status":"ok","mode":"fake"}\n' >"${json_out}"
    echo 'status=ok mode=fake direction=download throughput_mib/s=1.000 throughput_gbit/s=0.008 requests/s=10.000'
    ;;
  *)
    echo "unexpected fake mode: ${mode}" >&2
    exit 1
    ;;
esac
FAKE_PERF
chmod +x "${fake_store}/bin/coquic-perf"

cat > "${fake_bin_dir}/nix" <<'FAKE_NIX'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'nix\t%s\n' "$*" >>"${log_path}"
if [ "$1" = 'build' ] && [ "$2" = '--print-out-paths' ] && [ "$3" = '.#coquic-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_STORE:?}"
  exit 0
fi
if [ "$1" = 'build' ] && [ "$2" = '--no-link' ] && [ "$3" = '--print-out-paths' ] && [ "$4" = '.#coquic-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_STORE:?}"
  exit 0
fi
if [ "$1" = 'build' ] && [ "$2" = '--no-link' ] && [ "$3" = '.#coquic-perf-quictls-musl' ]; then
  exit 1
fi
exec /usr/bin/env nix "$@"
FAKE_NIX
chmod +x "${fake_bin_dir}/nix"

cat > "${fake_bin_dir}/taskset" <<'FAKE_TASKSET'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'taskset\t%s\n' "$*" >>"${log_path}"
[ "$1" = '-c' ] || {
  echo 'expected -c for fake taskset' >&2
  exit 1
}
shift 2
exec "$@"
FAKE_TASKSET
chmod +x "${fake_bin_dir}/taskset"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_STORE="${fake_store}" \
PERF_RESULTS_ROOT="${results_root}" \
bash "${script}" --preset smoke >/dev/null

[ -f "${results_root}/environment.txt" ] || {
  echo 'behavioral harness test missing environment.txt' >&2
  exit 1
}

[ -f "${results_root}/manifest.json" ] || {
  echo 'behavioral harness test missing manifest.json' >&2
  exit 1
}

for run_name in \
  smoke-socket-bulk-s1-c1-q1 \
  smoke-socket-rr-s1-c1-q4 \
  smoke-socket-crr-s1-c2-q1
  do
  [ -f "${results_root}/${run_name}.json" ] || {
    echo "behavioral harness test missing JSON result for ${run_name}" >&2
    exit 1
  }
  [ -f "${results_root}/${run_name}.txt" ] || {
    echo "behavioral harness test missing summary output for ${run_name}" >&2
    exit 1
  }
  [ -f "${results_root}/${run_name}.server.log" ] || {
    echo "behavioral harness test missing server log for ${run_name}" >&2
    exit 1
  }
done

grep -F -- $'nix\tbuild --print-out-paths .#coquic-quictls-musl' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use direct nix build path' >&2
  exit 1
}

grep -F -- $'taskset\t-c 2 ' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server taskset invocation' >&2
  exit 1
}

grep -F -- $'taskset\t-c 3 ' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing client taskset invocation' >&2
  exit 1
}

grep -F -- $'taskset\t-c 2 '"${fake_store}/bin/coquic-perf"' server' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server command shape' >&2
  exit 1
}

grep -F -- $'taskset\t-c 3 '"${fake_store}/bin/coquic-perf"' client' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing client command shape' >&2
  exit 1
}

echo 'perf harness contract looks correct'
