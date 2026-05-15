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

grep -F -- 'image_attr="${PERF_IMAGE_ATTR:-perf-image-quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing perf image attr default in harness script' >&2
  exit 1
}

grep -F -- 'image_tag="${PERF_IMAGE_TAG:-coquic-perf:quictls-musl}"' "${script}" >/dev/null || {
  echo 'missing perf image tag default in harness script' >&2
  exit 1
}

grep -F -- 'congestion_controls="${PERF_CONGESTION_CONTROLS:-newreno cubic bbr}"' "${script}" >/dev/null || {
  echo 'missing congestion-control default in harness script' >&2
  exit 1
}

grep -F -- 'nix build --print-out-paths ".#${image_attr}"' "${script}" >/dev/null || {
  echo 'missing nix image build in harness script' >&2
  exit 1
}

grep -F -- 'docker load -i "${image_path}"' "${script}" >/dev/null || {
  echo 'missing docker image load in harness script' >&2
  exit 1
}

grep -F -- 'docker network create "${network_name}"' "${script}" >/dev/null || {
  echo 'missing Docker bridge network creation in harness script' >&2
  exit 1
}

grep -F -- 'topology=docker-bridge-two-containers' "${script}" >/dev/null || {
  echo 'missing Docker bridge topology marker in harness script' >&2
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

if grep -F -- '--network host' "${script}" >/dev/null; then
  echo 'unexpected host-network Docker flag in bridge harness script' >&2
  exit 1
fi

if grep -F -- '--cap-add IPC_LOCK' "${script}" >/dev/null; then
  echo 'unexpected container capability override in bridge harness script' >&2
  exit 1
fi

if grep -F -- 'perf_bin=' "${script}" >/dev/null; then
  echo 'unexpected direct perf binary resolution in Docker harness script' >&2
  exit 1
fi

grep -F -- 'tests/fixtures:/certs:ro' "${script}" >/dev/null || {
  echo 'missing mounted test certificate directory in harness script' >&2
  exit 1
}

grep -F -- '--certificate-chain /certs/quic-server-cert.pem' "${script}" >/dev/null || {
  echo 'missing mounted server certificate path in harness script' >&2
  exit 1
}

grep -F -- '--private-key /certs/quic-server-key.pem' "${script}" >/dev/null || {
  echo 'missing mounted server key path in harness script' >&2
  exit 1
}

grep -F -- 'environment.txt' "${script}" >/dev/null || {
  echo 'missing environment snapshot in harness script' >&2
  exit 1
}

grep -F -- '"${results_root}"/*.cid' "${script}" >/dev/null || {
  echo 'missing stale server cid cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker rm -f "${server_name}"' "${script}" >/dev/null || {
  echo 'missing server container cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker rm -f "${client_name}"' "${script}" >/dev/null || {
  echo 'missing client container cleanup in harness script' >&2
  exit 1
}

grep -F -- 'docker network rm "${network_name}"' "${script}" >/dev/null || {
  echo 'missing Docker network cleanup in harness script' >&2
  exit 1
}

grep -F -- 'timeout --kill-after=5s "${run_timeout_seconds}s" docker run --rm' "${script}" >/dev/null || {
  echo 'missing bounded client container run in harness script' >&2
  exit 1
}

grep -F -- '--congestion-control "${congestion_control}"' "${script}" >/dev/null || {
  echo 'missing congestion-control forwarding in harness script' >&2
  exit 1
}

grep -F -- 'PERF_CONGESTION_CONTROLS   space-separated algorithms to run' "${script}" >/dev/null || {
  echo 'missing congestion-control usage text in harness script' >&2
  exit 1
}

grep -F -- 'usage: bash bench/run-host-matrix.sh [--preset smoke|ci]' "${script}" >/dev/null || {
  echo 'missing ci preset in harness usage' >&2
  exit 1
}

grep -F -- 'ci)' "${script}" >/dev/null || {
  echo 'missing ci preset case in harness script' >&2
  exit 1
}

smoke_runs=(
  '"socket bulk download 0 65536 65536 1 1 1 0ms 5s"'
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
  '"socket bulk download 0 1048576 none 4 1 1 0ms 60s"'
  '"socket rr stay 32 32 none 1 32 16 5s 45s"'
  '"socket crr stay 32 32 none 1 64 1 5s 45s"'
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

grep -F -- 'perf-image-quictls-musl' "${flake}" >/dev/null || {
  echo 'missing perf image package export in flake.nix' >&2
  exit 1
}

grep -F -- '.bench-results/' "${ignore_file}" >/dev/null || {
  echo 'missing benchmark results ignore rule' >&2
  exit 1
}

image_path="$(nix build --no-link --print-out-paths .#perf-image-quictls-musl)"
[ -f "${image_path}" ] || {
  echo 'real perf image package did not produce a tarball path' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
fake_bin_dir="${tmp_dir}/fake-bin"
fake_image="${tmp_dir}/fake-image.tar"
results_root="${tmp_dir}/results"
log_path="${tmp_dir}/invocations.log"
mkdir -p "${fake_bin_dir}" "${results_root}"
touch "${fake_image}"

cat > "${fake_bin_dir}/nix" <<'FAKE_NIX'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'nix\t%s\n' "$*" >>"${log_path}"
if [ "$1" = 'build' ] && [ "$2" = '--print-out-paths' ] && [ "$3" = '.#perf-image-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_IMAGE:?}"
  exit 0
fi
if [ "$1" = 'build' ] && [ "$2" = '--no-link' ] && [ "$3" = '--print-out-paths' ] && [ "$4" = '.#perf-image-quictls-musl' ]; then
  printf '%s\n' "${FAKE_PERF_IMAGE:?}"
  exit 0
fi
exec /usr/bin/env nix "$@"
FAKE_NIX
chmod +x "${fake_bin_dir}/nix"

cat > "${fake_bin_dir}/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'docker\t%s\n' "$*" >>"${log_path}"
case "$1" in
  load)
    [ "$2" = '-i' ] || {
      echo 'expected docker load -i' >&2
      exit 1
    }
    ;;
  image)
    [ "$2" = 'inspect' ] || {
      echo 'unexpected docker image command' >&2
      exit 1
    }
    ;;
  network)
    case "$2" in
      create)
        printf '%s\n' "${3:-fake-network}"
        ;;
      inspect)
        printf '[{"Name":"%s"}]\n' "${3:-fake-network}"
        ;;
      rm)
        ;;
      *)
        echo "unexpected docker network command: $2" >&2
        exit 1
        ;;
    esac
    ;;
  version)
    echo 'fake docker version'
    ;;
  info)
    echo 'fake docker info'
    ;;
  run)
    shift
    detached=0
    name=''
    args=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -d)
          detached=1
          shift
          ;;
        --rm)
          shift
          ;;
        --name)
          name="$2"
          shift 2
          ;;
        --network|--cpuset-cpus|-v)
          shift 2
          ;;
        --network=*)
          shift
          ;;
        *)
          args+=("$1")
          shift
          ;;
      esac
    done
    role_index=1
    if [ "${args[0]:-}" = 'coquic-perf:quictls-musl' ]; then
      role_index=1
    fi
    role="${args[${role_index}]:-}"
    congestion_control=''
    for ((i = 0; i < ${#args[@]}; i++)); do
      if [ "${args[$i]}" = '--congestion-control' ]; then
        congestion_control="${args[$((i + 1))]}"
      fi
    done
    case "${congestion_control}" in
      newreno|cubic|bbr)
        ;;
      *)
        echo "unexpected congestion-control: ${congestion_control}; args=${args[*]}" >&2
        exit 1
        ;;
    esac
    if [ "${detached}" -eq 1 ]; then
      [ "${role}" = 'server' ] || {
        echo "expected server role in detached docker run, got args=${args[*]}" >&2
        exit 1
      }
      printf 'fake-server-container-id\n'
      exit 0
    fi
    [ "${role}" = 'client' ] || {
      echo "expected client role in docker run, got args=${args[*]}" >&2
      exit 1
    }
    json_out=''
    for ((i = 0; i < ${#args[@]}; i++)); do
      if [ "${args[$i]}" = '--json-out' ]; then
        json_out="${args[$((i + 1))]}"
      fi
    done
    [ "${json_out}" = '/results/result.json' ] || {
      echo "unexpected json out: ${json_out}" >&2
      exit 1
    }
    printf '{"status":"ok","mode":"fake","congestion_control":"%s"}\n' "${congestion_control}" >"${FAKE_RESULTS_ROOT}/result.json"
    echo 'status=ok mode=fake direction=download throughput_mib/s=1.000 throughput_gbit/s=0.008 requests/s=10.000'
    ;;
  logs)
    echo 'fake server log'
    ;;
  rm)
    ;;
  *)
    echo "unexpected docker command: $1" >&2
    exit 1
    ;;
esac
FAKE_DOCKER
chmod +x "${fake_bin_dir}/docker"

cat > "${fake_bin_dir}/timeout" <<'FAKE_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
log_path="${FAKE_PERF_LOG:?}"
printf 'timeout\t%s\n' "$*" >>"${log_path}"
if [ "${1:-}" = '--kill-after=5s' ]; then
  shift
fi
shift
exec "$@"
FAKE_TIMEOUT
chmod +x "${fake_bin_dir}/timeout"

PATH="${fake_bin_dir}:$PATH" \
FAKE_PERF_LOG="${log_path}" \
FAKE_PERF_IMAGE="${fake_image}" \
FAKE_RESULTS_ROOT="${results_root}" \
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
  smoke-newreno-socket-bulk-s1-c1-q1 \
  smoke-newreno-socket-rr-s1-c1-q4 \
  smoke-newreno-socket-crr-s1-c2-q1 \
  smoke-cubic-socket-bulk-s1-c1-q1 \
  smoke-cubic-socket-rr-s1-c1-q4 \
  smoke-cubic-socket-crr-s1-c2-q1 \
  smoke-bbr-socket-bulk-s1-c1-q1 \
  smoke-bbr-socket-rr-s1-c1-q4 \
  smoke-bbr-socket-crr-s1-c2-q1
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

grep -F -- $'nix\tbuild --print-out-paths .#perf-image-quictls-musl' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not use image nix build path' >&2
  exit 1
}

grep -F -- $'docker\tload -i '"${fake_image}" "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not load Docker image' >&2
  exit 1
}

grep -F -- $'docker\tnetwork create coquic-perf-smoke-' "${log_path}" >/dev/null || {
  echo 'behavioral harness test did not create Docker bridge network' >&2
  exit 1
}

grep -F -- '--network coquic-perf-smoke-' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing bridge network on docker run' >&2
  exit 1
}

grep -F -- '--cpuset-cpus 2' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server cpuset' >&2
  exit 1
}

grep -F -- '--cpuset-cpus 3' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing client cpuset' >&2
  exit 1
}

grep -F -- 'tests/fixtures:/certs:ro' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing cert mount' >&2
  exit 1
}

grep -F -- '--certificate-chain /certs/quic-server-cert.pem' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server cert argument' >&2
  exit 1
}

grep -F -- '--private-key /certs/quic-server-key.pem' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing server key argument' >&2
  exit 1
}

grep -F -- '--congestion-control newreno' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing NewReno congestion-control argument' >&2
  exit 1
}

grep -F -- '--congestion-control cubic' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing CUBIC congestion-control argument' >&2
  exit 1
}

grep -F -- '--congestion-control bbr' "${log_path}" >/dev/null || {
  echo 'behavioral harness test missing BBR congestion-control argument' >&2
  exit 1
}

if grep -F -- '--network host' "${log_path}" >/dev/null; then
  echo 'behavioral harness test unexpectedly used host networking' >&2
  exit 1
fi

python3 - "${results_root}/manifest.json" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
if manifest.get("topology") != "docker-bridge-two-containers":
    raise SystemExit("manifest missing Docker bridge topology")
if manifest.get("image_tag") != "coquic-perf:quictls-musl":
    raise SystemExit("manifest missing perf image tag")
if manifest.get("image_attr") != "perf-image-quictls-musl":
    raise SystemExit("manifest missing perf image attr")
if manifest.get("congestion_controls") != ["newreno", "cubic", "bbr"]:
    raise SystemExit("manifest missing congestion-control list")
if len(manifest.get("runs", [])) != 9:
    raise SystemExit("manifest missing per-algorithm smoke runs")
seen = {run.get("congestion_control") for run in manifest.get("runs", [])}
if seen != {"newreno", "cubic", "bbr"}:
    raise SystemExit("manifest missing per-run congestion-control values")
PY

echo 'perf harness contract looks correct'
