#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${repo_root}"

fixtures_dir="${repo_root}/tests/fixtures"
interop_image="coquic-interop:boringssl-musl"
quicgo_image="martenseemann/quic-go-interop:latest"
case_timeout_seconds="${INTEROP_CASE_TIMEOUT_SECONDS:-40}"
root="$(mktemp -d)"

cleanup_root() {
  rm -rf "${root}"
}

cleanup_case() {
  local name=$1
  local net=$2
  set +e
  docker rm -f "${name}-client" "${name}-server" "${name}-sim" >/dev/null 2>&1 || true
  docker network rm "${net}" >/dev/null 2>&1 || true
}

print_case_logs() {
  local name=$1
  local base=$2

  echo "client logs:"
  docker logs "${name}-client" 2>&1 | sed -n '1,220p' || true
  echo "server logs:"
  docker logs "${name}-server" 2>&1 | sed -n '1,220p' || true
  if docker inspect "${name}-sim" >/dev/null 2>&1; then
    echo "sim logs:"
    docker logs "${name}-sim" 2>&1 | sed -n '1,120p' || true
  fi
  echo "downloads:"
  find "${base}/downloads" -maxdepth 3 -type f | sort | sed -n '1,40p' || true
  if [ -f "${base}/downloads/hello.txt" ]; then
    echo "downloaded contents:"
    sed -n '1,20p' "${base}/downloads/hello.txt" || true
  fi
}

run_case() {
  local name=$1
  local testcase=$2
  local server_kind=$3
  local client_kind=$4
  local need_sim=$5
  local net="${name}-net-$RANDOM"
  local base="${root}/${name}"
  local expected="hello from ${server_kind} ${testcase}"
  local wait_output
  local exit_code

  mkdir -p "${base}/www" "${base}/downloads" "${base}/client-logs" "${base}/server-logs"
  printf '%s\n' "${expected}" > "${base}/www/hello.txt"

  echo "== ${name} =="
  trap 'cleanup_case "'"${name}"'" "'"${net}"'"' RETURN

  docker network create "${net}" >/dev/null

  if [ "${need_sim}" = "1" ]; then
    docker run -d \
      --name "${name}-sim" \
      --network "${net}" \
      --network-alias sim \
      alpine:3.20 \
      sh -c "while true; do nc -lk -p 57832 >/dev/null 2>&1; done" >/dev/null
  fi

  if [ "${server_kind}" = "coquic" ]; then
    docker run -d \
      --name "${name}-server" \
      --network "${net}" \
      --network-alias server \
      -e ROLE=server \
      -e TESTCASE="${testcase}" \
      -e COQUIC_SKIP_SETUP=1 \
      -v "${base}/www:/www:ro" \
      -v "${fixtures_dir}/quic-server-cert.pem:/certs/cert.pem:ro" \
      -v "${fixtures_dir}/quic-server-key.pem:/certs/priv.key:ro" \
      -v "${base}/server-logs:/logs" \
      "${interop_image}" >/dev/null
  else
    docker run -d \
      --name "${name}-server" \
      --network "${net}" \
      --network-alias server \
      -e ROLE=server \
      -e TESTCASE="${testcase}" \
      -v "${base}/www:/www:ro" \
      -v "${fixtures_dir}/quic-server-cert.pem:/certs/cert.pem:ro" \
      -v "${fixtures_dir}/quic-server-key.pem:/certs/priv.key:ro" \
      -v "${base}/server-logs:/logs" \
      "${quicgo_image}" >/dev/null
  fi

  sleep 2

  if [ "${client_kind}" = "coquic" ]; then
    docker run -d \
      --name "${name}-client" \
      --network "${net}" \
      -e ROLE=client \
      -e TESTCASE="${testcase}" \
      -e REQUESTS="https://server/hello.txt" \
      -e COQUIC_SKIP_SETUP=1 \
      -e COQUIC_SKIP_WAIT=1 \
      -v "${base}/downloads:/downloads" \
      -v "${base}/client-logs:/logs" \
      "${interop_image}" >/dev/null
  else
    docker run -d \
      --name "${name}-client" \
      --network "${net}" \
      -e ROLE=client \
      -e TESTCASE="${testcase}" \
      -e REQUESTS="https://server/hello.txt" \
      -v "${base}/downloads:/downloads" \
      -v "${base}/client-logs:/logs" \
      "${quicgo_image}" >/dev/null
  fi

  if ! wait_output="$(timeout "${case_timeout_seconds}" docker wait "${name}-client" 2>/dev/null)"; then
    echo "case timed out after ${case_timeout_seconds}s: ${name}" >&2
    print_case_logs "${name}" "${base}"
    return 1
  fi

  exit_code="$(printf '%s\n' "${wait_output}" | tail -n1)"
  if [ "${exit_code}" != "0" ]; then
    echo "client exited with ${exit_code}: ${name}" >&2
    print_case_logs "${name}" "${base}"
    return 1
  fi

  if [ ! -f "${base}/downloads/hello.txt" ]; then
    echo "missing downloaded file for ${name}" >&2
    print_case_logs "${name}" "${base}"
    return 1
  fi

  if ! grep -qxF "${expected}" "${base}/downloads/hello.txt"; then
    echo "unexpected downloaded contents for ${name}" >&2
    print_case_logs "${name}" "${base}"
    return 1
  fi

  echo "PASS ${name}"
  trap - RETURN
  cleanup_case "${name}" "${net}"
}

trap cleanup_root EXIT

nix --option eval-cache false build .#interop-image-boringssl-musl
image_tar="$(nix path-info .#interop-image-boringssl-musl)"
docker load -i "${image_tar}" >/dev/null
docker pull "${quicgo_image}" >/dev/null

run_case "quicgo-client-handshake" handshake coquic quicgo 1
run_case "quicgo-client-transfer" transfer coquic quicgo 1
run_case "quicgo-server-handshake" handshake quicgo coquic 0
run_case "quicgo-server-transfer" transfer quicgo coquic 0

echo "All quic-go interop smoke cases passed."
